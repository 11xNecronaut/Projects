"""
Shared state across the three GUI views. Deliberately a plain object,
not a singleton/global — MainWindow owns one instance and hands it to
each view, which makes the views testable in isolation without needing
to fake global state.
"""

import hashlib
from dataclasses import dataclass
from typing import Optional

from ..crypto import kem


def fingerprint(public_key: bytes) -> str:
    """Short, human-checkable fingerprint of a public key — for
    eyeballing 'is this the key I think it is' without comparing 1184
    raw bytes. Not a security boundary by itself, just a sanity check,
    same role a PGP key fingerprint plays."""
    digest = hashlib.sha256(public_key).hexdigest()
    return " ".join(digest[i:i + 4] for i in range(0, 16, 4)).upper()


@dataclass
class AppState:
    current_keypair: Optional[kem.KeyPair] = None
    current_keystore_path: Optional[str] = None

    def is_unlocked(self) -> bool:
        return self.current_keypair is not None

    def public_key_fingerprint(self) -> Optional[str]:
        if self.current_keypair is None:
            return None
        return fingerprint(self.current_keypair.public_key)
