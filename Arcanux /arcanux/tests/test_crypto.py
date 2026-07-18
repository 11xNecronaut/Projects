"""
Crypto engine test suite. Every claim in the README about integrity
and confidentiality is only true if these pass.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from src.crypto import kem, kdf, aead, container


# ---------------------------------------------------------------------
# ML-KEM-768 (kem.py)
# ---------------------------------------------------------------------

def test_keypair_sizes():
    kp = kem.generate_keypair()
    assert len(kp.public_key) == kem.PUBLIC_KEY_SIZE
    assert len(kp.secret_key) == kem.SECRET_KEY_SIZE


def test_encapsulate_decapsulate_round_trip():
    kp = kem.generate_keypair()
    enc = kem.encapsulate(kp.public_key)
    recovered_secret = kem.decapsulate(kp.secret_key, enc.kem_ciphertext)
    assert recovered_secret == enc.shared_secret
    assert len(enc.shared_secret) == kem.SHARED_SECRET_SIZE


def test_decapsulate_with_wrong_secret_key_gives_different_secret():
    # ML-KEM is IND-CCA2 secure: decapsulating with the wrong key does
    # NOT raise an error, it deterministically produces a DIFFERENT
    # shared secret (implicit rejection). This is correct KEM behavior,
    # not a bug — it's what prevents chosen-ciphertext attacks. The
    # AEAD layer above is what actually rejects wrong keys loudly.
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()
    enc = kem.encapsulate(kp_a.public_key)
    wrong_secret = kem.decapsulate(kp_b.secret_key, enc.kem_ciphertext)
    assert wrong_secret != enc.shared_secret


def test_encapsulate_rejects_bad_key_size():
    with pytest.raises(ValueError):
        kem.encapsulate(b"too short")


# ---------------------------------------------------------------------
# KDF (kdf.py)
# ---------------------------------------------------------------------

def test_derive_aead_key_deterministic_for_same_input():
    secret = os.urandom(32)
    key1 = kdf.derive_aead_key(secret)
    key2 = kdf.derive_aead_key(secret)
    assert key1 == key2
    assert len(key1) == kdf.AEAD_KEY_SIZE


def test_derive_aead_key_domain_separation():
    secret = os.urandom(32)
    key_a = kdf.derive_aead_key(secret, context=b"context-a")
    key_b = kdf.derive_aead_key(secret, context=b"context-b")
    assert key_a != key_b


def test_password_derivation_round_trip_same_salt():
    result1 = kdf.derive_key_from_password("correct horse battery staple")
    result2 = kdf.derive_key_from_password("correct horse battery staple", salt=result1.salt)
    assert result1.key == result2.key


def test_password_derivation_different_passwords_different_keys():
    salt = os.urandom(kdf.ARGON2_SALT_SIZE)
    key1 = kdf.derive_key_from_password("password one", salt=salt).key
    key2 = kdf.derive_key_from_password("password two", salt=salt).key
    assert key1 != key2


# ---------------------------------------------------------------------
# AEAD (aead.py)
# ---------------------------------------------------------------------

def test_aead_encrypt_decrypt_round_trip():
    key = os.urandom(32)
    plaintext = b"the grocery list is not military-grade, calm down"
    sealed = aead.encrypt(key, plaintext)
    recovered = aead.decrypt(key, sealed)
    assert recovered == plaintext


def test_aead_tampered_ciphertext_rejected():
    key = os.urandom(32)
    sealed = aead.encrypt(key, b"secret payload")
    tampered_bytes = bytearray(sealed.ciphertext)
    tampered_bytes[0] ^= 0xFF
    tampered = aead.SealedData(nonce=sealed.nonce, ciphertext=bytes(tampered_bytes))
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(key, tampered)


def test_aead_wrong_key_rejected():
    key1 = os.urandom(32)
    key2 = os.urandom(32)
    sealed = aead.encrypt(key1, b"secret payload")
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(key2, sealed)


def test_aead_associated_data_mismatch_rejected():
    key = os.urandom(32)
    sealed = aead.encrypt(key, b"secret payload", associated_data=b"header-v1")
    with pytest.raises(aead.DecryptionError):
        aead.decrypt(key, sealed, associated_data=b"header-v2")


def test_aead_nonces_are_unique():
    key = os.urandom(32)
    nonces = {aead.encrypt(key, b"x").nonce for _ in range(1000)}
    assert len(nonces) == 1000


# ---------------------------------------------------------------------
# Container (container.py) — full seal/open integration
# ---------------------------------------------------------------------

def test_seal_open_round_trip():
    kp = kem.generate_keypair()
    plaintext = b"This is the real payload that gets hidden in an image."
    sealed_bytes = container.seal(kp.public_key, plaintext)
    recovered = container.open_container(kp.secret_key, sealed_bytes)
    assert recovered == plaintext


def test_seal_open_round_trip_empty_plaintext():
    kp = kem.generate_keypair()
    sealed_bytes = container.seal(kp.public_key, b"")
    recovered = container.open_container(kp.secret_key, sealed_bytes)
    assert recovered == b""


def test_seal_open_round_trip_large_plaintext():
    kp = kem.generate_keypair()
    plaintext = os.urandom(1_000_000)  # 1 MB
    sealed_bytes = container.seal(kp.public_key, plaintext)
    recovered = container.open_container(kp.secret_key, sealed_bytes)
    assert recovered == plaintext


def test_container_pack_unpack_round_trip():
    c = container.Container(
        kem_ciphertext=os.urandom(kem.CIPHERTEXT_SIZE),
        aead_nonce=os.urandom(aead.NONCE_SIZE),
        aead_ciphertext=os.urandom(64),
    )
    packed = c.pack()
    unpacked = container.Container.unpack(packed)
    assert unpacked == c


def test_container_rejects_bad_magic():
    junk = b"XXXX" + bytes(200)
    with pytest.raises(container.ContainerFormatError):
        container.Container.unpack(junk)


def test_container_rejects_truncated_data():
    kp = kem.generate_keypair()
    sealed_bytes = container.seal(kp.public_key, b"hello world")
    truncated = sealed_bytes[:10]
    with pytest.raises(container.ContainerFormatError):
        container.Container.unpack(truncated)


def test_open_container_wrong_secret_key_fails():
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()
    sealed_bytes = container.seal(kp_a.public_key, b"only kp_a should read this")
    with pytest.raises(aead.DecryptionError):
        container.open_container(kp_b.secret_key, sealed_bytes)


def test_open_container_tampered_header_fails():
    kp = kem.generate_keypair()
    sealed_bytes = bytearray(container.seal(kp.public_key, b"payload"))
    sealed_bytes[4] = 99  # flip the version byte
    with pytest.raises(container.ContainerFormatError):
        container.open_container(kp.secret_key, bytes(sealed_bytes))


def test_open_container_tampered_ciphertext_fails():
    kp = kem.generate_keypair()
    sealed_bytes = bytearray(container.seal(kp.public_key, b"payload"))
    sealed_bytes[-1] ^= 0xFF  # flip last byte of AEAD ciphertext/tag
    with pytest.raises(aead.DecryptionError):
        container.open_container(kp.secret_key, bytes(sealed_bytes))


@pytest.mark.parametrize("size", [0, 1, 31, 32, 33, 1024, 65536])
def test_seal_open_various_plaintext_sizes(size):
    kp = kem.generate_keypair()
    plaintext = os.urandom(size)
    sealed_bytes = container.seal(kp.public_key, plaintext)
    recovered = container.open_container(kp.secret_key, sealed_bytes)
    assert recovered == plaintext
