"""
Integration tests for the keystore and orchestrator — the full,
real-world "encrypt-then-embed, extract-then-decrypt" workflow, driven
through actual files on disk, exactly as the GUI will call it.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import numpy as np
import pytest
from PIL import Image

from src.crypto import kem, aead
from src.core import keystore, orchestrator


def _make_carrier(path, width=300, height=300):
    arr = np.random.randint(0, 256, (height, width, 3), dtype=np.uint8)
    Image.fromarray(arr, "RGB").save(path, format="PNG")


# ---------------------------------------------------------------------
# Keystore
# ---------------------------------------------------------------------

def test_keystore_save_load_round_trip(tmp_path):
    kp = kem.generate_keypair()
    path = tmp_path / "identity.arcx"
    keystore.save_keypair(kp, "correct horse battery staple", str(path))

    loaded = keystore.load_keypair("correct horse battery staple", str(path))
    assert loaded.public_key == kp.public_key
    assert loaded.secret_key == kp.secret_key


def test_keystore_wrong_password_rejected(tmp_path):
    kp = kem.generate_keypair()
    path = tmp_path / "identity.arcx"
    keystore.save_keypair(kp, "right password", str(path))

    with pytest.raises(keystore.WrongPasswordError):
        keystore.load_keypair("wrong password", str(path))


def test_keystore_load_public_key_without_password(tmp_path):
    kp = kem.generate_keypair()
    path = tmp_path / "identity.arcx"
    keystore.save_keypair(kp, "some password", str(path))

    public_only = keystore.load_public_key(str(path))
    assert public_only == kp.public_key


def test_keystore_rejects_garbage_file(tmp_path):
    path = tmp_path / "not_a_keystore.arcx"
    path.write_bytes(b"this is not a keystore file at all")
    with pytest.raises(keystore.KeystoreFormatError):
        keystore.load_keypair("any password", str(path))


# ---------------------------------------------------------------------
# Orchestrator — full protect/reveal workflow
# ---------------------------------------------------------------------

def test_protect_reveal_round_trip(tmp_path):
    kp = kem.generate_keypair()

    secret_file = tmp_path / "diary.txt"
    secret_file.write_text("Dear diary, today I built a post-quantum steganography tool.")

    carrier = tmp_path / "carrier.png"
    _make_carrier(carrier, width=200, height=200)

    output = tmp_path / "output.png"
    orchestrator.protect_file(str(secret_file), str(carrier), kp.public_key, str(output))

    assert output.exists()

    revealed = orchestrator.reveal_file(str(output), kp.secret_key)
    assert revealed.filename == "diary.txt"
    assert revealed.data == secret_file.read_bytes()


def test_protect_reveal_round_trip_binary_file(tmp_path):
    kp = kem.generate_keypair()

    binary_file = tmp_path / "photo.bin"
    binary_file.write_bytes(os.urandom(2000))

    carrier = tmp_path / "carrier.png"
    _make_carrier(carrier, width=300, height=300)

    output = tmp_path / "output.png"
    orchestrator.protect_file(str(binary_file), str(carrier), kp.public_key, str(output))

    revealed = orchestrator.reveal_file(str(output), kp.secret_key)
    assert revealed.filename == "photo.bin"
    assert revealed.data == binary_file.read_bytes()


def test_reveal_with_wrong_secret_key_fails(tmp_path):
    kp_a = kem.generate_keypair()
    kp_b = kem.generate_keypair()

    secret_file = tmp_path / "secret.txt"
    secret_file.write_text("only kp_a should be able to read this")

    carrier = tmp_path / "carrier.png"
    _make_carrier(carrier, width=200, height=200)

    output = tmp_path / "output.png"
    orchestrator.protect_file(str(secret_file), str(carrier), kp_a.public_key, str(output))

    with pytest.raises(aead.DecryptionError):
        orchestrator.reveal_file(str(output), kp_b.secret_key)


def test_protect_raises_when_file_too_large_for_carrier(tmp_path):
    kp = kem.generate_keypair()

    big_file = tmp_path / "big.bin"
    big_file.write_bytes(os.urandom(50_000))  # way more than a tiny image can hold

    carrier = tmp_path / "carrier.png"
    _make_carrier(carrier, width=20, height=20)  # tiny carrier

    output = tmp_path / "output.png"
    with pytest.raises(orchestrator.PayloadTooLargeError) as exc_info:
        orchestrator.protect_file(str(big_file), str(carrier), kp.public_key, str(output))

    # The error should carry concrete, useful numbers, not just "it failed"
    assert exc_info.value.container_size > exc_info.value.available_capacity
    assert exc_info.value.suggested_dimensions[0] > 20


def test_check_fits_matches_actual_protect_behavior(tmp_path):
    kp = kem.generate_keypair()

    small_file = tmp_path / "note.txt"
    small_file.write_text("small enough to fit")

    carrier = tmp_path / "carrier.png"
    _make_carrier(carrier, width=200, height=200)

    # check_fits should succeed without raising, and protect_file should
    # then also succeed — the pre-flight check and the real path must agree.
    estimated_size = orchestrator.check_fits(str(small_file), str(carrier))
    assert estimated_size > 0

    output = tmp_path / "output.png"
    orchestrator.protect_file(str(small_file), str(carrier), kp.public_key, str(output))
    revealed = orchestrator.reveal_file(str(output), kp.secret_key)
    assert revealed.data == small_file.read_bytes()


def test_output_path_forced_to_png_extension(tmp_path):
    kp = kem.generate_keypair()

    secret_file = tmp_path / "note.txt"
    secret_file.write_text("test")

    carrier = tmp_path / "carrier.png"
    _make_carrier(carrier, width=100, height=100)

    output = tmp_path / "output.jpg"  # deliberately wrong extension
    orchestrator.protect_file(str(secret_file), str(carrier), kp.public_key, str(output))

    actual_output = tmp_path / "output.png"
    assert actual_output.exists()
    assert not output.exists()  # the .jpg path should never have been written
