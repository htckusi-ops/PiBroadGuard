import hashlib
import io
import json
import logging
import platform
import uuid
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.device import Device
from app.models.finding import Finding
from app.models.scan_authorization import ScanAuthorization
from app.models.scan_result import ScanResult
from app.services import crypto_service
from app.core.config import settings

logger = logging.getLogger("pibroadguard.package")

BDSA_VERSION = "1.0"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _to_json(obj: Any) -> bytes:
    if hasattr(obj, "__dict__"):
        obj = {k: v for k, v in obj.__dict__.items() if not k.startswith("_")}
    return json.dumps(obj, default=str, ensure_ascii=False, indent=2).encode("utf-8")


def export_package(db: Session, assessment_id: int) -> bytes:
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise ValueError(f"Assessment {assessment_id} not found")

    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    scan_results = db.query(ScanResult).filter(ScanResult.assessment_id == assessment_id).all()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    auth = db.query(ScanAuthorization).filter(ScanAuthorization.assessment_id == assessment_id).first()

    def model_to_dict(obj):
        if obj is None:
            return None
        d = {}
        for c in obj.__class__.__table__.columns:
            val = getattr(obj, c.name, None)
            if hasattr(val, "isoformat"):
                val = val.isoformat()
            d[c.name] = val
        return d

    device_json = _to_json(model_to_dict(device))
    assessment_json = _to_json(model_to_dict(assessment))
    scan_results_json = _to_json([model_to_dict(s) for s in scan_results])
    findings_json = _to_json([model_to_dict(f) for f in findings])
    auth_json = _to_json(model_to_dict(auth))

    # Rules snapshot
    try:
        with open(settings.pibg_rules_path, "rb") as f:
            rules_data = f.read()
    except Exception:
        rules_data = b"{}"

    checksums = {
        "device.json": _sha256(device_json),
        "assessment.json": _sha256(assessment_json),
        "scan_results.json": _sha256(scan_results_json),
        "findings.json": _sha256(findings_json),
        "authorization.json": _sha256(auth_json),
        "rules_snapshot.yaml": _sha256(rules_data),
    }

    # Raw nmap XML
    raw_xml = b""
    for sr in scan_results:
        if sr.raw_nmap_output:
            raw_xml = sr.raw_nmap_output.encode("utf-8")
            break
    checksums["scan_raw.xml"] = _sha256(raw_xml)

    nmap_version = "unknown"
    try:
        import subprocess
        r = subprocess.run(["nmap", "--version"], capture_output=True, text=True, timeout=5)
        nmap_version = r.stdout.splitlines()[0].split("version ")[-1].split(" ")[0] if r.stdout else "unknown"
    except Exception:
        pass

    manifest = {
        "bdsa_version": BDSA_VERSION,
        "package_id": str(uuid.uuid4()),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_on_host": platform.node(),
        "phase": "scan_complete",
        "device_id": assessment.device_id,
        "assessment_id": assessment_id,
        "checksums": checksums,
        "nmap_version": nmap_version,
        "scan_profile": assessment.scan_profile,
        "rules_version": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
    }
    manifest_json = _to_json(manifest)

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("manifest.json", manifest_json)
        zf.writestr("device.json", device_json)
        zf.writestr("assessment.json", assessment_json)
        zf.writestr("scan_results.json", scan_results_json)
        zf.writestr("scan_raw.xml", raw_xml)
        zf.writestr("findings.json", findings_json)
        zf.writestr("authorization.json", auth_json)
        zf.writestr("rules_snapshot.yaml", rules_data)

    logger.info(f"Created package for assessment {assessment_id}")
    return buf.getvalue()


def verify_package(data: bytes) -> dict:
    errors = []
    warnings = []
    manifest = {}

    # Decrypt if needed
    if crypto_service.is_encrypted(data):
        if not settings.pibg_shared_secret:
            return {"valid": False, "errors": ["Paket ist verschlüsselt, kein Shared Secret konfiguriert"], "warnings": [], "manifest": {}}
        try:
            data = crypto_service.decrypt(data, settings.pibg_shared_secret)
        except ValueError as e:
            return {"valid": False, "errors": [str(e)], "warnings": [], "manifest": {}}

    try:
        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            manifest_raw = zf.read("manifest.json")
            manifest = json.loads(manifest_raw)

            # Version check
            if manifest.get("bdsa_version") != BDSA_VERSION:
                warnings.append(f"BDSA-Version {manifest.get('bdsa_version')} – erwartet {BDSA_VERSION}")

            # Checksum verification
            for fname, expected_sha in manifest.get("checksums", {}).items():
                try:
                    actual_data = zf.read(fname)
                    actual_sha = _sha256(actual_data)
                    if actual_sha != expected_sha:
                        errors.append(f"Checksummen-Fehler: {fname}")
                except KeyError:
                    errors.append(f"Datei fehlt im Paket: {fname}")

    except zipfile.BadZipFile:
        errors.append("Ungültiges ZIP-Archiv")
    except Exception as e:
        errors.append(f"Fehler beim Lesen des Pakets: {e}")

    return {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "manifest": manifest}


def import_package(db, data: bytes, imported_by: str) -> dict:
    if crypto_service.is_encrypted(data):
        if not settings.pibg_shared_secret:
            raise ValueError("Paket ist verschlüsselt, kein Shared Secret konfiguriert")
        data = crypto_service.decrypt(data, settings.pibg_shared_secret)

    verification = verify_package(data)
    if not verification["valid"]:
        raise ValueError(f"Paket-Verifikation fehlgeschlagen: {verification['errors']}")

    from app.models.device import Device
    from app.models.assessment import Assessment
    from app.models.scan_result import ScanResult
    from app.models.finding import Finding
    from app.models.import_log import ImportLog

    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        manifest = json.loads(zf.read("manifest.json"))
        device_data = json.loads(zf.read("device.json"))
        assessment_data = json.loads(zf.read("assessment.json"))
        scan_results_data = json.loads(zf.read("scan_results.json"))
        findings_data = json.loads(zf.read("findings.json"))

    # Import device (check if exists)
    device = Device(
        manufacturer=device_data.get("manufacturer"),
        model=device_data.get("model"),
        device_type=device_data.get("device_type"),
        ip_address=device_data.get("ip_address"),
        hostname=device_data.get("hostname"),
        firmware_version=device_data.get("firmware_version"),
        location=device_data.get("location"),
        network_segment=device_data.get("network_segment"),
        production_criticality=device_data.get("production_criticality"),
        notes=f"[Imported] {device_data.get('notes') or ''}",
    )
    db.add(device)
    db.flush()

    assessment = Assessment(
        device_id=device.id,
        status="imported",
        scan_profile=assessment_data.get("scan_profile"),
        technical_score=assessment_data.get("technical_score", 100),
        operational_score=assessment_data.get("operational_score", 100),
        compensation_score=assessment_data.get("compensation_score", 100),
        lifecycle_score=assessment_data.get("lifecycle_score", 100),
        vendor_score=assessment_data.get("vendor_score", 100),
        overall_rating=assessment_data.get("overall_rating"),
    )
    db.add(assessment)
    db.flush()

    for sr in scan_results_data:
        db.add(ScanResult(
            assessment_id=assessment.id,
            port=sr.get("port"),
            protocol=sr.get("protocol"),
            service_name=sr.get("service_name"),
            service_product=sr.get("service_product"),
            service_version=sr.get("service_version"),
            state=sr.get("state"),
            extra_info=sr.get("extra_info"),
        ))

    for fd in findings_data:
        db.add(Finding(
            assessment_id=assessment.id,
            rule_key=fd.get("rule_key"),
            title=fd.get("title"),
            severity=fd.get("severity"),
            description=fd.get("description"),
            evidence=fd.get("evidence"),
            recommendation=fd.get("recommendation"),
            broadcast_context=fd.get("broadcast_context"),
            status=fd.get("status", "open"),
        ))

    import hashlib as _hl
    pkg_sha = _hl.sha256(data).hexdigest()
    log = ImportLog(
        package_id=manifest.get("package_id"),
        assessment_id=assessment.id,
        imported_by=imported_by,
        source_host=manifest.get("created_on_host"),
        package_checksum=pkg_sha,
        status="success",
    )
    db.add(log)
    db.commit()

    logger.info(f"Imported package {manifest.get('package_id')} as assessment {assessment.id}")
    return {"assessment_id": assessment.id, "device_id": device.id, "manifest": manifest}
