import hashlib
import logging
import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("pibroadguard.crypto")

MAGIC = b"BDSA"
VERSION = b"\x01"
PBKDF2_ITERATIONS = 100_000


def _derive_key(secret: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(secret.encode("utf-8"))


def encrypt(data: bytes, shared_secret: str) -> bytes:
    salt = os.urandom(16)
    iv = os.urandom(12)
    key = _derive_key(shared_secret, salt)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, data, None)
    return MAGIC + VERSION + salt + iv + ciphertext_with_tag


def decrypt(data: bytes, shared_secret: str) -> bytes:
    if not is_encrypted(data):
        raise ValueError("Not an encrypted BDSA file (missing magic bytes)")
    offset = len(MAGIC) + len(VERSION)
    salt = data[offset:offset + 16]
    offset += 16
    iv = data[offset:offset + 12]
    offset += 12
    ciphertext_with_tag = data[offset:]
    key = _derive_key(shared_secret, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(iv, ciphertext_with_tag, None)
    except Exception as e:
        logger.warning(f"Decryption failed: {e}")
        raise ValueError("Decryption failed – wrong key or corrupted data") from e


def is_encrypted(data: bytes) -> bool:
    return data[:4] == MAGIC


def get_key_fingerprint(shared_secret: str) -> str:
    digest = hashlib.sha256(shared_secret.encode("utf-8")).hexdigest()
    return f"sha256:{digest[:16]}"
