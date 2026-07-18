"""
LSB steganography for image carriers (PNG/BMP).

MVP implementation: sequential least-significant-bit embedding across
the R, G, B channels. Straightforward, well-understood, and known to
be detectable by dedicated statistical steganalysis (chi-square, RS
analysis) — that limitation is documented in docs/THREAT_MODEL.md, not
hidden. Phase 2 adds randomized bit-distribution as an anti-detection
improvement; MVP intentionally ships without it so baseline behavior
is easy to test and reason about independent of a seed/key.

Input carrier format is flexible — PNG, BMP, JPEG, or anything Pillow can
decode all work equally well, because embedding happens against the
DECODED pixel array, not the compressed file bytes. What matters is the
OUTPUT: it is always saved as PNG (lossless), because any re-compression
after embedding — including re-saving as JPEG — would destroy the LSB
data. A JPEG carrier that has already been compressed once is not
"more compressed" by being read and embedded into; only saving the
*result* as a lossy format would break it, and this code never does that.
"""

import numpy as np
from PIL import Image

from .capacity import calculate_image_capacity_bytes, InsufficientCapacityError


LENGTH_PREFIX_BYTES = 4  # 32-bit big-endian payload length, embedded first


class ExtractionError(Exception):
    """Raised when a payload can't be validly extracted from an image —
    either it never had Arcanux data embedded, or it's corrupted."""
    pass


def _bytes_to_bits(data: bytes) -> np.ndarray:
    return np.unpackbits(np.frombuffer(data, dtype=np.uint8))


def _bits_to_bytes(bits: np.ndarray) -> bytes:
    return np.packbits(bits).tobytes()


def embed_bytes(image: Image.Image, payload: bytes) -> Image.Image:
    """
    Embed `payload` into `image` using sequential LSB embedding.
    Returns a NEW image (input is not modified). Raises
    InsufficientCapacityError if the payload doesn't fit.
    """
    capacity = calculate_image_capacity_bytes(image)
    if len(payload) > capacity:
        raise InsufficientCapacityError(
            f"Payload is {len(payload)} bytes but this image can only hold "
            f"{capacity} bytes. Use a larger image or a smaller payload."
        )

    rgb_image = image.convert("RGB")
    pixels = np.array(rgb_image, dtype=np.uint8)
    flat = pixels.reshape(-1).copy()  # flatten H*W*3 channel values

    length_header = len(payload).to_bytes(LENGTH_PREFIX_BYTES, "big")
    payload_bits = _bytes_to_bits(length_header + payload)

    # Clear the LSB of every channel value we're about to use, then set
    # it to the corresponding payload bit.
    n = len(payload_bits)
    flat[:n] = (flat[:n] & 0xFE) | payload_bits

    stego_pixels = flat.reshape(pixels.shape)
    return Image.fromarray(stego_pixels, mode="RGB")


def extract_bytes(image: Image.Image) -> bytes:
    """
    Extract a payload previously embedded with embed_bytes(). Reads the
    32-bit length header first, then exactly that many payload bytes.
    Raises ExtractionError if the image is too small to plausibly
    contain a valid header/payload (i.e. it wasn't a Arcanux carrier,
    or it's corrupted/truncated).
    """
    rgb_image = image.convert("RGB")
    pixels = np.array(rgb_image, dtype=np.uint8)
    flat = pixels.reshape(-1)

    header_bits_needed = LENGTH_PREFIX_BYTES * 8
    if flat.size < header_bits_needed:
        raise ExtractionError("Image too small to contain a valid length header.")

    header_bits = flat[:header_bits_needed] & 1
    header_bytes = _bits_to_bytes(header_bits)
    payload_length = int.from_bytes(header_bytes, "big")

    total_bits_needed = header_bits_needed + payload_length * 8
    if flat.size < total_bits_needed:
        raise ExtractionError(
            f"Declared payload length ({payload_length} bytes) exceeds what "
            "this image can hold. This image was not produced by "
            "Arcanux, or the file has been corrupted/re-encoded."
        )

    payload_bits = flat[header_bits_needed:total_bits_needed] & 1
    return _bits_to_bytes(payload_bits)
