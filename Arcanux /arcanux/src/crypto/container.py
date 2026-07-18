"""
Arcanux container format — the thing that actually gets embedded
into a carrier image or audio file.

Layout (all integers big-endian):

    [4 bytes]  magic       b"ARCX"
    [1 byte]   version     0x01
    [1 byte]   algorithm   0x01 = ML-KEM-768 + ChaCha20-Poly1305
    [1088 bytes] kem_ciphertext   (fixed size for ML-KEM-768)
    [12 bytes]   aead_nonce
    [N bytes]    aead_ciphertext  (plaintext length + 16-byte Poly1305 tag)

The 6-byte header (magic + version + algorithm) is passed to the AEAD
as associated data, so if anyone flips the version or algorithm byte
after the fact, decryption fails the auth check rather than silently
misinterpreting the rest of the container. That header is authenticated
but never secret — it has to be readable before decryption to know
which algorithm to even attempt.

This module is the orchestration point between kem.py, kdf.py, and
aead.py. Nothing here touches files or images — that's core/orchestrator.py
and stego/*.py. seal()/open_container() operate purely on bytes in,
bytes out.
"""

import struct
from dataclasses import dataclass

from . import kem
from . import kdf
from . import aead


MAGIC = b"ARCX"
VERSION = 1
ALG_ML_KEM_768_CHACHA20POLY1305 = 1

_HEADER_STRUCT = struct.Struct(">4sBB")  # magic, version, algorithm
HEADER_SIZE = _HEADER_STRUCT.size        # 6 bytes — public, stable API

# Kept for backwards compatibility with any code still referencing the
# old private name; new code should use HEADER_SIZE.
_HEADER_SIZE = HEADER_SIZE

AEAD_TAG_SIZE = 16  # Poly1305 tag, appended to every ChaCha20-Poly1305 ciphertext


def overhead_bytes() -> int:
    """
    Total fixed byte overhead a sealed container adds on top of the raw
    plaintext: header + KEM ciphertext + AEAD nonce + AEAD tag. This is
    the number the steganography/orchestration layer needs to compute
    carrier capacity requirements — exposed here as a stable public
    function instead of making callers reconstruct it from internals.
    """
    return HEADER_SIZE + kem.CIPHERTEXT_SIZE + aead.NONCE_SIZE + AEAD_TAG_SIZE


class ContainerFormatError(Exception):
    """Raised when container bytes are malformed, truncated, or use an
    unsupported/unrecognized version or algorithm."""
    pass


@dataclass(frozen=True)
class Container:
    kem_ciphertext: bytes
    aead_nonce: bytes
    aead_ciphertext: bytes

    def pack(self) -> bytes:
        header = _HEADER_STRUCT.pack(MAGIC, VERSION, ALG_ML_KEM_768_CHACHA20POLY1305)
        return header + self.kem_ciphertext + self.aead_nonce + self.aead_ciphertext

    @staticmethod
    def unpack(data: bytes) -> "Container":
        if len(data) < _HEADER_SIZE:
            raise ContainerFormatError("Data too short to contain a valid header.")

        magic, version, algorithm = _HEADER_STRUCT.unpack(data[:_HEADER_SIZE])
        if magic != MAGIC:
            raise ContainerFormatError(
                f"Bad magic bytes: expected {MAGIC!r}, got {magic!r}. "
                "This is not a Arcanux container."
            )
        if version != VERSION:
            raise ContainerFormatError(f"Unsupported container version: {version}")
        if algorithm != ALG_ML_KEM_768_CHACHA20POLY1305:
            raise ContainerFormatError(f"Unsupported algorithm ID: {algorithm}")

        offset = _HEADER_SIZE
        kem_ct_end = offset + kem.CIPHERTEXT_SIZE
        nonce_end = kem_ct_end + aead.NONCE_SIZE

        if len(data) < nonce_end:
            raise ContainerFormatError("Data too short: truncated KEM ciphertext or nonce.")

        kem_ciphertext = data[offset:kem_ct_end]
        aead_nonce = data[kem_ct_end:nonce_end]
        aead_ciphertext = data[nonce_end:]

        if len(aead_ciphertext) == 0:
            raise ContainerFormatError("Data too short: missing AEAD ciphertext.")

        return Container(
            kem_ciphertext=kem_ciphertext,
            aead_nonce=aead_nonce,
            aead_ciphertext=aead_ciphertext,
        )


def _header_bytes() -> bytes:
    return _HEADER_STRUCT.pack(MAGIC, VERSION, ALG_ML_KEM_768_CHACHA20POLY1305)


def seal(recipient_public_key: bytes, plaintext: bytes) -> bytes:
    """
    Full encrypt path: ML-KEM encapsulate -> HKDF -> AEAD encrypt -> pack.
    Returns the raw container bytes, ready to hand to the steganography
    embedding layer.
    """
    encapsulation = kem.encapsulate(recipient_public_key)
    aead_key = kdf.derive_aead_key(encapsulation.shared_secret)
    sealed = aead.encrypt(aead_key, plaintext, associated_data=_header_bytes())

    container = Container(
        kem_ciphertext=encapsulation.kem_ciphertext,
        aead_nonce=sealed.nonce,
        aead_ciphertext=sealed.ciphertext,
    )
    return container.pack()


def open_container(recipient_secret_key: bytes, container_bytes: bytes) -> bytes:
    """
    Full decrypt path: unpack -> ML-KEM decapsulate -> HKDF -> AEAD decrypt.
    Raises ContainerFormatError for malformed input, or
    aead.DecryptionError if the auth tag doesn't verify (wrong key,
    tampering, or corruption).
    """
    container = Container.unpack(container_bytes)
    shared_secret = kem.decapsulate(recipient_secret_key, container.kem_ciphertext)
    aead_key = kdf.derive_aead_key(shared_secret)

    sealed = aead.SealedData(nonce=container.aead_nonce, ciphertext=container.aead_ciphertext)
    return aead.decrypt(aead_key, sealed, associated_data=_header_bytes())
