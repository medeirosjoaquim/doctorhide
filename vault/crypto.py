"""Zero-knowledge encryption helpers.

The project passphrase is never stored. The encryption key is derived from the
passphrase + a per-project salt with PBKDF2, and used with Fernet (AES-128-CBC +
HMAC) to encrypt secret values. The server keeps only the salt, a verifier, and
the ciphertext — never the passphrase or the plaintext.
"""
import base64
import os

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

DEFAULT_ITERATIONS = 600_000
SALT_BYTES = 16
_VERIFY_TOKEN = b"doctorhide-verify"


def generate_salt() -> str:
    """A fresh random salt, base64-encoded for storage."""
    return base64.b64encode(os.urandom(SALT_BYTES)).decode()


def derive_key(passphrase: str, salt_b64: str, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Derive a Fernet key from the passphrase and salt. Returns a urlsafe-base64
    key ready to pass to Fernet()."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=base64.b64decode(salt_b64),
        iterations=iterations,
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode()))


def make_verifier(key: bytes) -> str:
    """A token that proves a later-derived key matches this one, without storing
    the passphrase."""
    return Fernet(key).encrypt(_VERIFY_TOKEN).decode()


def verify_key(key: bytes, verifier: str) -> bool:
    try:
        return Fernet(key).decrypt(verifier.encode()) == _VERIFY_TOKEN
    except InvalidToken:
        return False


def encrypt(key: bytes, plaintext: str) -> str:
    return Fernet(key).encrypt(plaintext.encode()).decode()


def decrypt(key: bytes, ciphertext: str) -> str:
    return Fernet(key).decrypt(ciphertext.encode()).decode()
