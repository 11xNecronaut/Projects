"""
Capacity calculation for image steganography carriers.

The single most common failure mode in a steganography tool is a user
trying to hide a payload that simply doesn't fit, and getting a
confusing error (or worse, silent corruption) instead of a clear
answer up front. This module exists so the GUI can check BEFORE
attempting to embed, not after.

Note on alpha channels: images with an alpha channel are converted to
RGB before embedding, meaning the alpha channel is dropped from the
output stego image entirely. Deliberate MVP simplification — embedding
in alpha is possible but adds complexity for images that are frequently
fully opaque anyway. Documented limitation, not an oversight.
"""

from PIL import Image


LENGTH_PREFIX_BYTES = 4
BITS_PER_CHANNEL_VALUE = 1  # 1 LSB per R/G/B channel value in MVP


class InsufficientCapacityError(Exception):
    """Raised when a payload does not fit in the given carrier."""
    pass


def calculate_image_capacity_bytes(image: Image.Image) -> int:
    """
    Return the maximum PAYLOAD size (in bytes) this image can hold,
    already accounting for the 4-byte length header Arcanux embeds
    alongside the payload. This is what the GUI/orchestrator should
    compare a sealed container's size against before attempting to embed.
    """
    width, height = image.size
    channels = 3  # RGB after conversion, alpha dropped
    total_bits = width * height * channels * BITS_PER_CHANNEL_VALUE
    total_bytes = total_bits // 8
    usable_bytes = total_bytes - LENGTH_PREFIX_BYTES
    return max(usable_bytes, 0)


def required_pixel_count_for_payload(payload_size_bytes: int) -> int:
    """
    Inverse of calculate_image_capacity_bytes: given a payload size,
    return the minimum number of pixels needed to hold it. Useful for
    GUI messages like "you need at least ~14,000 pixels for this file
    (e.g. a 120x120 image)."
    """
    total_bytes_needed = payload_size_bytes + LENGTH_PREFIX_BYTES
    total_bits_needed = total_bytes_needed * 8
    channels = 3
    pixels_needed = -(-total_bits_needed // channels)  # ceil division
    return pixels_needed
