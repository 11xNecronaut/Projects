"""
ML-KEM-768 (Kyber) key encapsulation wrapper.

NIST FIPS 203 standardized post-quantum key encapsulation mechanism.
Backed by pqcrypto (PQClean reference implementations, prebuilt wheels).

This module does exactly one job: produce and consume ML-KEM keypairs
and shared secrets. It does not know about files, AEAD, or passwords —
that separation is deliberate. A crypto primitive wrapper that also
does file I/O is a crypto primitive wrapper you can't unit test cleanly.
"""

from dataclasses import dataclass
from pqcrypto.kem import ml_kem_768


PUBLIC_KEY_SIZE = ml_kem_768.PUBLIC_KEY_SIZE      # 1184 bytes
SECRET_KEY_SIZE = ml_kem_768.SECRET_KEY_SIZE      # 2400 bytes
CIPHERTEXT_SIZE = ml_kem_768.CIPHERTEXT_SIZE      # 1088 bytes
SHARED_SECRET_SIZE = ml_kem_768.PLAINTEXT_SIZE    # 32 bytes


@dataclass(frozen=True)
class KeyPair:
    public_key: bytes
    secret_key: bytes

    def __post_init__(self):
        if len(self.public_key) != PUBLIC_KEY_SIZE:
            raise ValueError(
                f"public_key must be {PUBLIC_KEY_SIZE} bytes, got {len(self.public_key)}"
            )
        if len(self.secret_key) != SECRET_KEY_SIZE:
            raise ValueError(
                f"secret_key must be {SECRET_KEY_SIZE} bytes, got {len(self.secret_key)}"
            )


@dataclass(frozen=True)
class Encapsulation:
    """Result of encapsulating against a recipient's public key."""
    kem_ciphertext: bytes   # send this to the recipient
    shared_secret: bytes    # keep local, feed into KDF -> AEAD key


def generate_keypair() -> KeyPair:
    """Generate a new ML-KEM-768 keypair."""
    public_key, secret_key = ml_kem_768.generate_keypair()
    return KeyPair(public_key=public_key, secret_key=secret_key)


def encapsulate(public_key: bytes) -> Encapsulation:
    """
    Encapsulate a fresh shared secret against a recipient's public key.
    Used by the sender/encryptor. Produces a ciphertext to embed in the
    container and a shared secret to derive the AEAD key from.
    """
    if len(public_key) != PUBLIC_KEY_SIZE:
        raise ValueError(
            f"public_key must be {PUBLIC_KEY_SIZE} bytes, got {len(public_key)}"
        )
    kem_ciphertext, shared_secret = ml_kem_768.encrypt(public_key)
    return Encapsulation(kem_ciphertext=kem_ciphertext, shared_secret=shared_secret)


def decapsulate(secret_key: bytes, kem_ciphertext: bytes) -> bytes:
    """
    Recover the shared secret from a KEM ciphertext using the recipient's
    secret key. Used by the receiver/decryptor.
    """
    if len(secret_key) != SECRET_KEY_SIZE:
        raise ValueError(
            f"secret_key must be {SECRET_KEY_SIZE} bytes, got {len(secret_key)}"
        )
    if len(kem_ciphertext) != CIPHERTEXT_SIZE:
        raise ValueError(
            f"kem_ciphertext must be {CIPHERTEXT_SIZE} bytes, got {len(kem_ciphertext)}"
        )
    return ml_kem_768.decrypt(secret_key, kem_ciphertext)
