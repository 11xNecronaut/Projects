"""
Steganography engine test suite. Covers round-trip correctness, capacity
enforcement, and extraction failure modes (corrupted/non-stego images).
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import pytest
from PIL import Image

from src.stego import capacity, image_embed


def _random_image(width: int, height: int, mode: str = "RGB") -> Image.Image:
    channels = {"RGB": 3, "RGBA": 4, "L": 1}[mode]
    shape = (height, width, channels) if channels > 1 else (height, width)
    arr = np.random.randint(0, 256, shape, dtype=np.uint8)
    return Image.fromarray(arr, mode)


# ---------------------------------------------------------------------
# Capacity
# ---------------------------------------------------------------------

def test_capacity_matches_expected_formula():
    img = _random_image(100, 50)
    expected = (100 * 50 * 3) // 8 - capacity.LENGTH_PREFIX_BYTES
    assert capacity.calculate_image_capacity_bytes(img) == expected


def test_capacity_never_negative_for_tiny_image():
    img = _random_image(1, 1)
    assert capacity.calculate_image_capacity_bytes(img) >= 0


def test_required_pixel_count_is_sufficient():
    payload_size = 2000
    pixels_needed = capacity.required_pixel_count_for_payload(payload_size)
    # A square image with at least that many pixels must have enough capacity
    side = int(pixels_needed ** 0.5) + 1
    img = _random_image(side, side)
    assert capacity.calculate_image_capacity_bytes(img) >= payload_size


# ---------------------------------------------------------------------
# Embed / extract round trips
# ---------------------------------------------------------------------

@pytest.mark.parametrize("size", [10, 50, 200])
@pytest.mark.parametrize("payload_len", [0, 1, 100, 1000])
def test_embed_extract_round_trip(size, payload_len):
    img = _random_image(size, size)
    payload = os.urandom(payload_len)
    if payload_len > capacity.calculate_image_capacity_bytes(img):
        pytest.skip("payload too large for this image size, covered by capacity tests")
    stego = image_embed.embed_bytes(img, payload)
    recovered = image_embed.extract_bytes(stego)
    assert recovered == payload


def test_embed_extract_survives_png_disk_round_trip(tmp_path):
    img = _random_image(80, 80)
    payload = b"This must survive a real PNG save and reload." * 3
    stego = image_embed.embed_bytes(img, payload)

    path = tmp_path / "carrier.png"
    stego.save(path, format="PNG")
    reloaded = Image.open(path)
    recovered = image_embed.extract_bytes(reloaded)
    assert recovered == payload


def test_embed_does_not_mutate_original_image():
    img = _random_image(50, 50)
    original_bytes = img.tobytes()
    image_embed.embed_bytes(img, b"some payload")
    assert img.tobytes() == original_bytes


def test_embed_handles_rgba_input_by_dropping_alpha():
    img = _random_image(50, 50, mode="RGBA")
    payload = b"rgba input should still work"
    stego = image_embed.embed_bytes(img, payload)
    assert stego.mode == "RGB"
    assert image_embed.extract_bytes(stego) == payload


def test_embed_handles_grayscale_input():
    img = _random_image(50, 50, mode="L")
    payload = b"grayscale input converted to rgb"
    stego = image_embed.embed_bytes(img, payload)
    assert image_embed.extract_bytes(stego) == payload


def test_exact_capacity_boundary_fits():
    img = _random_image(20, 20)
    max_payload = capacity.calculate_image_capacity_bytes(img)
    payload = os.urandom(max_payload)
    stego = image_embed.embed_bytes(img, payload)
    assert image_embed.extract_bytes(stego) == payload


# ---------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------

def test_embed_raises_when_payload_too_large():
    img = _random_image(10, 10)
    max_payload = capacity.calculate_image_capacity_bytes(img)
    oversized = os.urandom(max_payload + 1)
    with pytest.raises(capacity.InsufficientCapacityError):
        image_embed.embed_bytes(img, oversized)


def test_extract_raises_on_image_with_no_embedded_data():
    # A "clean" image will have a garbage length header (whatever the
    # LSBs of a random image happen to spell out), which should either
    # produce garbage bytes or, if the declared length is absurd
    # relative to image size, raise ExtractionError. We force the
    # absurd-length case deterministically here.
    img = _random_image(10, 10)  # tiny image, 300 bits ~ 37 bytes capacity
    pixels = np.array(img)
    flat = pixels.reshape(-1).copy()
    # Force the length header's LSBs to declare an impossibly large payload
    huge_length = (2**32 - 1)
    header_bits = np.unpackbits(np.frombuffer(huge_length.to_bytes(4, "big"), dtype=np.uint8))
    flat[:32] = (flat[:32] & 0xFE) | header_bits
    tampered = Image.fromarray(flat.reshape(pixels.shape), mode="RGB")

    with pytest.raises(image_embed.ExtractionError):
        image_embed.extract_bytes(tampered)


def test_extract_raises_on_image_too_small_for_header():
    # A 1x1 image has 3 channel values = 3 bits, less than the 32 bits
    # needed just for the length header.
    img = _random_image(1, 1)
    with pytest.raises(image_embed.ExtractionError):
        image_embed.extract_bytes(img)
