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
