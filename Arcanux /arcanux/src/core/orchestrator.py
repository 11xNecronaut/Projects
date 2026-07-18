"""
Orchestrator — the encrypt-then-embed and extract-then-decrypt workflows.

This is the only module that knows about BOTH the crypto engine and the
steganography engine. Keeping that coupling in one place (rather than
scattering crypto calls through the stego code or vice versa) is what
makes each half independently testable — which is exactly what
tests/test_crypto.py and tests/test_stego.py already proved in isolation.

Payload wire format (what actually gets sealed and embedded):

    [1 byte]  original_filename_length
    [N bytes] original_filename (utf-8)
    [rest]    original file contents

This lets reveal_file() hand back both the recovered bytes AND the
original filename/extension, so the GUI can restore "photo.jpg" instead
of a nameless blob. This wrapping happens HERE, not inside container.py
— the crypto container format doesn't need to know or care about
filenames, that's an orchestration-layer concern.
"""

import struct
from dataclasses import dataclass
from pathlib import Path

from PIL import Image

from ..crypto import container
from ..stego import capacity as stego_capacity
from ..stego import image_embed


MAX_FILENAME_BYTES = 255  # fits in a single length-prefix byte


class PayloadTooLargeError(Exception):
    """Raised when the file-to-protect, once sealed, won't fit in the
    chosen carrier image. Carries the numbers needed to explain why."""

    def __init__(self, container_size: int, available_capacity: int, suggested_dimensions: tuple):
        self.container_size = container_size
        self.available_capacity = available_capacity
        self.suggested_dimensions = suggested_dimensions
        w, h = suggested_dimensions
        super().__init__(
            f"Sealed payload is {container_size:,} bytes but this carrier "
            f"image only holds {available_capacity:,} bytes. Try a carrier "
            f"of at least {w}x{h} pixels, or choose a smaller file to protect."
        )


@dataclass(frozen=True)
class RevealedFile:
    filename: str
    data: bytes


def _wrap_payload(filename: str, data: bytes) -> bytes:
    name_bytes = filename.encode("utf-8")
    if len(name_bytes) > MAX_FILENAME_BYTES:
        # Truncate rather than fail outright — losing part of a filename
        # is recoverable annoyance, not data loss of the actual file.
        name_bytes = name_bytes[:MAX_FILENAME_BYTES]
    return struct.pack(">B", len(name_bytes)) + name_bytes + data


def _unwrap_payload(wrapped: bytes) -> RevealedFile:
    if len(wrapped) < 1:
        raise ValueError("Wrapped payload is empty — cannot contain a filename header.")
    name_len = wrapped[0]
    if len(wrapped) < 1 + name_len:
        raise ValueError("Wrapped payload truncated: filename header exceeds payload size.")
    filename = wrapped[1:1 + name_len].decode("utf-8", errors="replace")
    data = wrapped[1 + name_len:]
    return RevealedFile(filename=filename, data=data)


def check_fits(input_file_path: str, carrier_image_path: str) -> int:
    """
    Pre-flight check: does the file at input_file_path fit in the
    carrier at carrier_image_path once sealed? Returns the exact
    container size in bytes on success. Raises PayloadTooLargeError
    with concrete numbers on failure. Call this from the GUI before
    protect_file() to give the user an answer instantly rather than
    after a slow encrypt-then-fail.
    """
    file_size = Path(input_file_path).stat().st_size
    filename_overhead = 1 + min(len(Path(input_file_path).name.encode("utf-8")), MAX_FILENAME_BYTES)
    # ML-KEM ciphertext + AEAD nonce + AEAD tag + container header are
    # fixed-size overhead added by container.seal(); container.py exposes
    # this directly so we never need to know its internal layout here.
    estimated_container_size = container.overhead_bytes() + filename_overhead + file_size

    with Image.open(carrier_image_path) as img:
        width, height = img.size
    report_capacity = stego_capacity.calculate_image_capacity_bytes(
        Image.new("RGB", (width, height))
    )

    if estimated_container_size > report_capacity:
        suggested = stego_capacity.required_pixel_count_for_payload(estimated_container_size)
        side = int(suggested ** 0.5) + 1
        raise PayloadTooLargeError(
            container_size=estimated_container_size,
            available_capacity=report_capacity,
            suggested_dimensions=(side, side),
        )
    return estimated_container_size


def protect_file(input_file_path: str, carrier_image_path: str, recipient_public_key: bytes,
                  output_image_path: str) -> None:
    """
    Full encrypt-then-embed workflow:
      1. Read the file to protect.
      2. Wrap it with its original filename.
      3. Seal it (ML-KEM encapsulate -> HKDF -> ChaCha20-Poly1305 encrypt).
      4. Check it fits in the carrier (raises PayloadTooLargeError if not).
      5. Embed it into the carrier image via LSB.
      6. Save the result as PNG (lossless — required for LSB to survive).
    """
    input_path = Path(input_file_path)
    file_bytes = input_path.read_bytes()
    wrapped = _wrap_payload(input_path.name, file_bytes)

    sealed_container = container.seal(recipient_public_key, wrapped)

    with Image.open(carrier_image_path) as carrier:
        carrier_capacity = stego_capacity.calculate_image_capacity_bytes(carrier)
        if len(sealed_container) > carrier_capacity:
            suggested = stego_capacity.required_pixel_count_for_payload(len(sealed_container))
            side = int(suggested ** 0.5) + 1
            raise PayloadTooLargeError(
                container_size=len(sealed_container),
                available_capacity=carrier_capacity,
                suggested_dimensions=(side, side),
            )
        stego_image = image_embed.embed_bytes(carrier, sealed_container)

    output_path = Path(output_image_path)
    if output_path.suffix.lower() != ".png":
        output_path = output_path.with_suffix(".png")
    stego_image.save(output_path, format="PNG")


def reveal_file(stego_image_path: str, recipient_secret_key: bytes) -> RevealedFile:
    """
    Full extract-then-decrypt workflow:
      1. Extract the embedded container bytes from the stego image.
      2. Open the container (ML-KEM decapsulate -> HKDF -> AEAD decrypt +
         verify). Raises aead.DecryptionError if the key is wrong or the
         data was tampered with.
      3. Unwrap the filename header.
    Returns a RevealedFile with the original filename and file bytes.
    """
    with Image.open(stego_image_path) as stego_image:
        sealed_container = image_embed.extract_bytes(stego_image)

    wrapped = container.open_container(recipient_secret_key, sealed_container)
    return _unwrap_payload(wrapped)
