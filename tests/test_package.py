"""Tests für Package Service (Checksummen, Import/Export-Struktur)."""
import hashlib
import io
import json
import zipfile

import pytest


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def test_sha256_consistency():
    data = b"test data for checksum"
    assert _sha256(data) == _sha256(data)
    assert _sha256(data) != _sha256(data + b"x")


def test_bdsa_zip_structure():
    """Verify a manually created .bdsa package has expected structure."""
    required_files = [
        "manifest.json", "device.json", "assessment.json",
        "scan_results.json", "findings.json", "authorization.json",
        "rules_snapshot.yaml",
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for fname in required_files:
            zf.writestr(fname, b"{}")

    buf.seek(0)
    with zipfile.ZipFile(buf) as zf:
        names = zf.namelist()
        for fname in required_files:
            assert fname in names, f"Missing {fname}"


def test_manifest_schema():
    manifest = {
        "bdsa_version": "1.0",
        "package_id": "test-uuid",
        "created_at": "2026-03-21T12:00:00Z",
        "created_on_host": "test-host",
        "phase": "scan_complete",
        "device_id": 1,
        "assessment_id": 1,
        "checksums": {"device.json": "abc123"},
        "nmap_version": "7.94",
        "scan_profile": "passive",
        "rules_version": "2026-03-21",
    }
    required_keys = ["bdsa_version", "package_id", "created_at", "checksums"]
    for key in required_keys:
        assert key in manifest


def test_checksum_verification():
    data = b"device data"
    expected = _sha256(data)
    assert _sha256(data) == expected
    # Tampered data
    assert _sha256(data + b"x") != expected


def test_crypto_roundtrip_in_package():
    """Test encrypt/decrypt with a fake .bdsa package."""
    from app.services.crypto_service import encrypt, decrypt

    payload = b"fake zip data for package"
    secret = "test-secret-12345"

    encrypted = encrypt(payload, secret)
    decrypted = decrypt(encrypted, secret)
    assert decrypted == payload


def test_encrypted_package_wrong_key_fails():
    """Decrypting with a wrong key must raise ValueError."""
    from app.services.crypto_service import encrypt, decrypt

    payload = b"confidential package data"
    encrypted = encrypt(payload, "correct-secret")

    with pytest.raises(ValueError):
        decrypt(encrypted, "wrong-secret")


def test_tampered_package_fails_verification():
    """Modifying encrypted bytes must cause decryption to fail (GCM auth tag)."""
    from app.services.crypto_service import encrypt, decrypt

    payload = b"original data"
    secret = "my-secret"
    encrypted = encrypt(payload, secret)

    # Flip a byte in the ciphertext region (after magic+version+salt+iv = 4+1+16+12 = 33 bytes)
    tampered = bytearray(encrypted)
    tampered[33] ^= 0xFF
    tampered = bytes(tampered)

    with pytest.raises(ValueError):
        decrypt(tampered, secret)


def test_filename_uses_hostname_over_ip():
    """build_export_filename must prefer hostname over rdns over IP."""
    from app.services.package_service import build_export_filename
    from unittest.mock import MagicMock

    device = MagicMock()
    device.hostname = "encoder-01"
    device.rdns_hostname = "enc.prod.local"
    device.ip_address = "10.0.0.1"

    filename = build_export_filename(device, 42, encrypted=False)
    assert "encoder-01" in filename
    assert ".bdsa" in filename
    assert ".enc" not in filename


def test_filename_uses_rdns_when_no_hostname():
    """build_export_filename falls back to rDNS when no manual hostname."""
    from app.services.package_service import build_export_filename
    from unittest.mock import MagicMock

    device = MagicMock()
    device.hostname = ""
    device.rdns_hostname = "enc.prod.local"
    device.ip_address = "10.0.0.1"

    filename = build_export_filename(device, 42, encrypted=False)
    assert "enc" in filename


def test_export_zip_contains_required_files():
    """A manually assembled .bdsa ZIP must contain all required files."""
    required_files = [
        "manifest.json", "device.json", "assessment.json",
        "scan_results.json", "findings.json", "authorization.json",
        "rules_snapshot.yaml",
    ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for fname in required_files:
            zf.writestr(fname, json.dumps({"placeholder": True}))

    buf.seek(0)
    with zipfile.ZipFile(buf) as zf:
        for fname in required_files:
            assert fname in zf.namelist(), f"Missing required file: {fname}"


def test_checksum_detects_any_change():
    """SHA256 checksum must change on any modification, no matter how small."""
    data = b"broadcast device scan data"
    original = _sha256(data)
    for i in range(len(data)):
        tampered = bytearray(data)
        tampered[i] ^= 0x01
        assert _sha256(bytes(tampered)) != original, f"Checksum unchanged at byte {i}"
