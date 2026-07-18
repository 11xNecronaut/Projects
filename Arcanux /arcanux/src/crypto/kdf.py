"""
Key derivation functions.

Two distinct jobs, deliberately kept separate:

1. derive_aead_key   — stretches the ML-KEM shared secret (already high
                        entropy, 32 bytes) into a domain-separated AEAD key
                        via HKDF. Fast, not meant to resist brute force
                        (the input is already a strong secret).

2. derive_key_from_password — protects the user's LOCAL secret key file
                        with a password using Argon2id, which IS meant to
                        resist brute force (the input is human-chosen and
                        weak). Mixing these two up is a classic mistake:
                        using HKDF on a password, or Argon2id on an
                        already-random secret, either wastes CPU or leaves
                        a weak point. Keep them separate on purpose.
"""

import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id


AEAD_KEY_SIZE = 32          # 256-bit key for ChaCha20-Poly1305
ARGON2_SALT_SIZE = 16
ARGON2_KEY_SIZE = 32

# Argon2id parameters — tuned for interactive desktop use (roughly
# 0.3-0.8s on typical hardware). These are deliberately conservative
# but not so heavy that unlocking your own keystore feels broken.
# Values follow OWASP's recommended minimums for Argon2id.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST_KIB = 65536   # 64 MiB
ARGON2_PARALLELISM = 4


def derive_aead_key(shared_secret: bytes, context: bytes = b"arcanux-aead-v1") -> bytes:
    """
    Derive a ChaCha20-Poly1305 key from an ML-KEM shared secret using HKDF.
    `context` provides domain separation so this key can never collide
    with a key derived for a different purpose from the same secret.
    """
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AEAD_KEY_SIZE,
        salt=None,
        info=context,
    )
    return hkdf.derive(shared_secret)


@dataclass(frozen=True)
class PasswordDerivedKey:
    key: bytes
    salt: bytes


def derive_key_from_password(password: str, salt: bytes | None = None) -> PasswordDerivedKey:
    """
    Derive a key-encryption-key from a user password using Argon2id.
    If `salt` is None, a fresh random salt is generated (do this when
    protecting a NEW secret key). Pass the stored salt back in when
    unlocking an EXISTING secret key.
    """
    if salt is None:
        salt = os.urandom(ARGON2_SALT_SIZE)
    elif len(salt) != ARGON2_SALT_SIZE:
        raise ValueError(f"salt must be {ARGON2_SALT_SIZE} bytes, got {len(salt)}")

    kdf = Argon2id(
        salt=salt,
        length=ARGON2_KEY_SIZE,
        iterations=ARGON2_TIME_COST,
        lanes=ARGON2_PARALLELISM,
        memory_cost=ARGON2_MEMORY_COST_KIB,
    )
    key = kdf.derive(password.encode("utf-8"))
    return PasswordDerivedKey(key=key, salt=salt)
