"""
Local keystore — protects a user's ML-KEM secret key at rest using a
password (Argon2id-derived key -> ChaCha20-Poly1305), so the secret key
is never sitting on disk in plaintext.

The public key is stored unencrypted in the same file — public keys
are, by definition, not secret; encrypting them would add friction for
zero security benefit and is a common over-engineering mistake to avoid.

File format (all integers big-endian):

    [4 bytes]  magic         b"ARKS"
    [1 byte]   version       0x01
    [16 bytes] argon2_salt
    [12 bytes] aead_nonce
    [4 bytes]  public_key_len
    [N bytes]  public_key            (plaintext)
    [4 bytes]  encrypted_secret_len
    [M bytes]  encrypted_secret_key  (AEAD ciphertext + 16-byte tag)
"""

import struct
from dataclasses import dataclass

from ..crypto import kem, kdf, aead


MAGIC = b"ARKS"
VERSION = 1

_FIXED_HEADER = struct.Struct(">4sB16s12sI")  # magic, version, salt, nonce, pubkey_len


class KeystoreFormatError(Exception):
    """Raised when a keystore file is malformed, truncated, or has an
    unsupported version."""
    pass


class WrongPasswordError(Exception):
    """Raised when the supplied password fails to decrypt the secret key.
    Deliberately does not reveal whether the file itself is otherwise
    valid, to avoid giving an attacker a useful oracle."""
    pass


@dataclass(frozen=True)
class Keystore:
    public_key: bytes
    encrypted_secret_key: bytes
    salt: bytes
    nonce: bytes

    def pack(self) -> bytes:
        header = _FIXED_HEADER.pack(
            MAGIC, VERSION, self.salt, self.nonce, len(self.public_key)
        )
        secret_len = struct.pack(">I", len(self.encrypted_secret_key))
        return header + self.public_key + secret_len + self.encrypted_secret_key

    @staticmethod
    def unpack(data: bytes) -> "Keystore":
        fixed_size = _FIXED_HEADER.size
        if len(data) < fixed_size:
            raise KeystoreFormatError("File too short to be a valid keystore.")

        magic, version, salt, nonce, pubkey_len = _FIXED_HEADER.unpack(data[:fixed_size])
        if magic != MAGIC:
            raise KeystoreFormatError(f"Bad magic bytes: not a Arcanux keystore file.")
        if version != VERSION:
            raise KeystoreFormatError(f"Unsupported keystore version: {version}")

        offset = fixed_size
        pubkey_end = offset + pubkey_len
        if len(data) < pubkey_end + 4:
            raise KeystoreFormatError("File truncated: missing public key or secret length.")

        public_key = data[offset:pubkey_end]
        secret_len = struct.unpack(">I", data[pubkey_end:pubkey_end + 4])[0]
        secret_start = pubkey_end + 4
        secret_end = secret_start + secret_len

        if len(data) < secret_end:
            raise KeystoreFormatError("File truncated: missing encrypted secret key.")

        encrypted_secret_key = data[secret_start:secret_end]
        return Keystore(
            public_key=public_key,
            encrypted_secret_key=encrypted_secret_key,
            salt=salt,
            nonce=nonce,
        )


def save_keypair(keypair: kem.KeyPair, password: str, path: str) -> None:
    """Encrypt and write a keypair to disk, protected by `password`."""
    derived = kdf.derive_key_from_password(password)
    sealed = aead.encrypt(derived.key, keypair.secret_key, associated_data=keypair.public_key)

    keystore = Keystore(
        public_key=keypair.public_key,
        encrypted_secret_key=sealed.ciphertext,
        salt=derived.salt,
        nonce=sealed.nonce,
    )
    with open(path, "wb") as f:
        f.write(keystore.pack())


def load_keypair(password: str, path: str) -> kem.KeyPair:
    """
    Load and decrypt a keypair from disk. Raises WrongPasswordError if
    the password is incorrect, or KeystoreFormatError if the file is
    malformed/not a keystore.
    """
    with open(path, "rb") as f:
        data = f.read()

    keystore = Keystore.unpack(data)
    derived = kdf.derive_key_from_password(password, salt=keystore.salt)

    sealed = aead.SealedData(nonce=keystore.nonce, ciphertext=keystore.encrypted_secret_key)
    try:
        secret_key = aead.decrypt(derived.key, sealed, associated_data=keystore.public_key)
    except aead.DecryptionError as e:
        raise WrongPasswordError("Incorrect password for this keystore file.") from e

    return kem.KeyPair(public_key=keystore.public_key, secret_key=secret_key)


def load_public_key(path: str) -> bytes:
    """Read just the public key from a keystore file — no password needed.
    Useful for sharing your public key without touching the secret key."""
    with open(path, "rb") as f:
        data = f.read()
    return Keystore.unpack(data).public_key
