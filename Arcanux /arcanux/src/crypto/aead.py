"""
ChaCha20-Poly1305 authenticated encryption wrapper.

This is where integrity actually comes from in Arcanux — not from a
signature scheme. The Poly1305 tag proves the ciphertext (and any
associated data) has not been modified since encryption. If that tag
doesn't verify, decrypt() raises; there is no partial/best-effort output.
"""

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.exceptions import InvalidTag


NONCE_SIZE = 12  # 96 bits, required size for ChaCha20-Poly1305


class DecryptionError(Exception):
    """Raised when AEAD authentication fails — ciphertext was tampered
    with, corrupted, or the wrong key was used. Deliberately does not
    distinguish which, to avoid leaking oracle information."""
    pass


@dataclass(frozen=True)
class SealedData:
    nonce: bytes
    ciphertext: bytes  # includes the appended 16-byte auth tag


def encrypt(key: bytes, plaintext: bytes, associated_data: bytes = b"") -> SealedData:
    """
    Encrypt plaintext with a fresh random nonce. `associated_data` is
    authenticated but not encrypted — use it for container metadata
    (version, algorithm ID) that must not be tampered with but doesn't
    need to be secret.
    """
    nonce = os.urandom(NONCE_SIZE)
    aead = ChaCha20Poly1305(key)
    ciphertext = aead.encrypt(nonce, plaintext, associated_data)
    return SealedData(nonce=nonce, ciphertext=ciphertext)


def decrypt(key: bytes, sealed: SealedData, associated_data: bytes = b"") -> bytes:
    """
    Decrypt and verify. Raises DecryptionError if the auth tag doesn't
    match — meaning wrong key, corrupted data, or tampering.
    """
    aead = ChaCha20Poly1305(key)
    try:
        return aead.decrypt(sealed.nonce, sealed.ciphertext, associated_data)
    except InvalidTag as e:
        raise DecryptionError(
            "Authentication failed: wrong key, corrupted data, or tampering detected."
        ) from e
