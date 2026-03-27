import json
import logging
import xml.etree.ElementTree as _ET
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from jinja2 import Environment, FileSystemLoader

from app.models.assessment import Assessment
from app.models.device import Device
from app.models.finding import Finding
from app.models.manual_finding import ManualFinding
from app.models.scan_authorization import ScanAuthorization
from app.models.scan_result import ScanResult
from app.models.vendor_info import VendorInformation

logger = logging.getLogger("pibroadguard.report")

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


def _rating_label(rating: str) -> str:
    return {
        "green": "🟢 Geeignet",
        "yellow": "🟡 Geeignet mit Auflagen",
        "orange": "🟠 Begrenzt einsetzbar",
        "red": "🔴 Nicht freigegeben",
    }.get(rating or "", rating or "—")


def _decision_label(decision: str) -> str:
    return {
        "approved": "Freigegeben",
        "approved_with_conditions": "Freigegeben mit Auflagen",
        "deferred": "Zurückgestellt",
        "rejected": "Abgelehnt",
    }.get(decision or "", decision or "—")


def _status_label(status: str) -> str:
    return {
        "open": "Offen",
        "compensated": "Kompensiert",
        "accepted": "Akzeptiert",
        "false_positive": "False Positive",
    }.get(status or "", status or "—")


def _prio_label(prio: str) -> str:
    return {"immediate": "Sofort", "short_term": "Kurzfristig", "long_term": "Langfristig"}.get(prio or "", prio or "")


def _format_date(val) -> str:
    if val is None:
        return "—"
    if isinstance(val, str):
        return val[:10]
    return val.strftime("%d.%m.%Y") if hasattr(val, "strftime") else str(val)


def _extract_nmap_version_from_results(scan_results) -> str:
    """Extract nmap version string from the raw XML stored in any scan result."""
    for sr in scan_results:
        raw = getattr(sr, "raw_nmap_output", None)
        if not raw:
            continue
        try:
            root = _ET.fromstring(raw)
            v = root.get("version")
            if v:
                return v
        except _ET.ParseError:
            continue
    return "unknown"


def _build_env() -> Environment:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES_DIR)))
    env.filters["rating_label"] = _rating_label
    env.filters["decision_label"] = _decision_label
    env.filters["status_label"] = _status_label
    env.filters["prio_label"] = _prio_label
    env.filters["date"] = _format_date
    return env


def _build_context(db, assessment: Assessment) -> Dict[str, Any]:
    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    scan_results = db.query(ScanResult).filter(ScanResult.assessment_id == assessment.id).all()
    findings = db.query(Finding).filter(Finding.assessment_id == assessment.id).all()
    manual_findings = db.query(ManualFinding).filter(ManualFinding.assessment_id == assessment.id).all()
    vendor_info = db.query(VendorInformation).filter(VendorInformation.assessment_id == assessment.id).first()
    auth = db.query(ScanAuthorization).filter(ScanAuthorization.assessment_id == assessment.id).first()

    findings_sorted = sorted(
        findings,
        key=lambda f: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(f.severity or "info", 4)
    )

    # Load scan profile details (nmap flags + description) for the report
    nmap_command = None
    scan_profile_label = assessment.scan_profile or "—"
    scan_profile_description = None
    try:
        from app.models.scan_profile import ScanProfile
        import json as _json
        sp = db.query(ScanProfile).filter(ScanProfile.name == assessment.scan_profile).first()
        if sp:
            scan_profile_label = sp.label
            scan_profile_description = sp.description
            flags = _json.loads(sp.nmap_flags)
            nmap_command = "nmap " + " ".join(flags) + " <target>"
    except Exception:
        pass

    # Collect raw nmap output – use the first result that has it
    nmap_raw_output = None
    for sr in scan_results:
        raw = getattr(sr, "raw_nmap_output", None)
        if raw:
            nmap_raw_output = raw
            break

    # Collect scan_effects manual findings for discovery report
    scan_effects = [mf for mf in manual_findings if mf.category == "scan_effects"]

    # Authorization date string for discovery report
    authorization = auth
    if auth:
        auth_date = getattr(auth, "authorization_date", None)
        auth.__dict__.setdefault("authorized_by_date", _format_date(auth_date))

    return {
        "device": device,
        "assessment": assessment,
        "scan_results": scan_results,
        "findings": findings_sorted,
        "manual_findings": manual_findings,
        "vendor_info": vendor_info,
        "auth": auth,
        "authorization": authorization,
        "scan_effects": scan_effects,
        "action_items": [],
        "nmap_version": _extract_nmap_version_from_results(scan_results),
        "nmap_command": nmap_command,
        "scan_profile_label": scan_profile_label,
        "scan_profile_description": scan_profile_description,
        "nmap_raw_output": nmap_raw_output,
        "generated_at": datetime.utcnow(),
    }


def generate_markdown(db, assessment: Assessment) -> str:
    env = _build_env()
    template = env.get_template("report.md.j2")
    ctx = _build_context(db, assessment)
    return template.render(**ctx)


def generate_html(db, assessment: Assessment) -> str:
    env = _build_env()
    scan_mode = getattr(assessment, "scan_mode", None) or "assessment"
    template_name = "report_discovery.html.j2" if scan_mode == "discovery" else "report.html.j2"
    template = env.get_template(template_name)
    ctx = _build_context(db, assessment)
    return template.render(**ctx)


def generate_json(db, assessment: Assessment) -> str:
    ctx = _build_context(db, assessment)
    data = {
        "device": _model_to_dict(ctx["device"]),
        "assessment": _model_to_dict(ctx["assessment"]),
        "scan_results": [_model_to_dict(s) for s in ctx["scan_results"]],
        "findings": [_model_to_dict(f) for f in ctx["findings"]],
        "vendor_info": _model_to_dict(ctx["vendor_info"]) if ctx["vendor_info"] else None,
        "auth": _model_to_dict(ctx["auth"]) if ctx["auth"] else None,
        "generated_at": ctx["generated_at"].isoformat(),
    }
    return json.dumps(data, default=str, ensure_ascii=False, indent=2)


def _model_to_dict(obj) -> Optional[Dict]:
    if obj is None:
        return None
    d = {}
    for c in obj.__class__.__table__.columns:
        val = getattr(obj, c.name, None)
        if hasattr(val, "isoformat"):
            val = val.isoformat()
        d[c.name] = val
    return d
