"""Tests für den Crypto Service (AES-256-GCM round-trip)."""
import pytest
from app.services.crypto_service import encrypt, decrypt, is_encrypted, get_key_fingerprint


SECRET = "test-shared-secret-12345"
WRONG_SECRET = "wrong-secret"


def test_encrypt_decrypt_roundtrip():
    data = b"Hello, PiBroadGuard!"
    encrypted = encrypt(data, SECRET)
    assert encrypted != data
    decrypted = decrypt(encrypted, SECRET)
    assert decrypted == data


def test_is_encrypted_true():
    data = b"some data"
    encrypted = encrypt(data, SECRET)
    assert is_encrypted(encrypted) is True


def test_is_encrypted_false():
    assert is_encrypted(b"plain text") is False
    assert is_encrypted(b"\x00\x00\x00\x00") is False


def test_wrong_key_raises():
    data = b"secret data"
    encrypted = encrypt(data, SECRET)
    with pytest.raises(ValueError):
        decrypt(encrypted, WRONG_SECRET)


def test_corrupted_data_raises():
    data = b"secret data"
    encrypted = bytearray(encrypt(data, SECRET))
    encrypted[-1] ^= 0xFF  # Flip last byte
    with pytest.raises(ValueError):
        decrypt(bytes(encrypted), SECRET)


def test_fingerprint_format():
    fp = get_key_fingerprint(SECRET)
    assert fp.startswith("sha256:")
    assert len(fp) > 10


def test_same_key_same_fingerprint():
    fp1 = get_key_fingerprint(SECRET)
    fp2 = get_key_fingerprint(SECRET)
    assert fp1 == fp2


def test_different_key_different_fingerprint():
    fp1 = get_key_fingerprint(SECRET)
    fp2 = get_key_fingerprint(WRONG_SECRET)
    assert fp1 != fp2


def test_large_data():
    data = b"x" * 1024 * 1024  # 1 MB
    encrypted = encrypt(data, SECRET)
    decrypted = decrypt(encrypted, SECRET)
    assert decrypted == data


def test_empty_data():
    data = b""
    encrypted = encrypt(data, SECRET)
    decrypted = decrypt(encrypted, SECRET)
    assert decrypted == data
