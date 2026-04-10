import logging
from datetime import datetime, timezone
from typing import List

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_credentials
from app.models.assessment import Assessment
from app.models.audit_log import AuditLog
from app.models.device import Device
from app.models.cve_cache import CveCache
from app.models.finding import Finding
from app.models.manual_finding import ManualFinding
from app.models.scan_authorization import ScanAuthorization
from app.models.scan_result import ScanResult
from app.models.vendor_info import VendorInformation
from app.models.action_items import ActionItem
from app.schemas.assessment import (
    AssessmentCreate, AssessmentRead, AssessmentUpdate,
    FindingUpdate, ManualFindingCreate, ManualFindingRead,
    ScanAuthorizationCreate, ScanAuthorizationRead,
    VendorInfoCreate, VendorInfoRead,
    ActionItemCreate, ActionItemRead,
)
from app.schemas.finding import FindingRead
from app.services import scoring_service
from app.services.rule_engine import QUESTION_CATALOG

logger = logging.getLogger("pibroadguard.api")
router = APIRouter(tags=["assessments"])


def _get_assessment_or_404(assessment_id: int, db: Session) -> Assessment:
    a = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not a:
        raise HTTPException(404, "Assessment nicht gefunden")
    return a


@router.post("/devices/{device_id}/assessments", response_model=AssessmentRead, status_code=201)
def create_assessment(
    device_id: int,
    body: AssessmentCreate,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    device = db.query(Device).filter(Device.id == device_id, Device.deleted == False).first()
    if not device:
        raise HTTPException(404, "Gerät nicht gefunden")
    assessment = Assessment(
        device_id=device_id,
        scan_profile=body.scan_profile,
        status="draft",
        overall_rating="unrated",
        technical_score=0,
        operational_score=0,
        compensation_score=0,
        lifecycle_score=0,
        vendor_score=0,
        manual_nmos_enabled=True,
        manual_ptp_enabled=True,
        manual_network_arch_enabled=True,
    )
    db.add(assessment)
    db.commit()
    db.refresh(assessment)

    # Pre-populate manual findings from the most recent previous assessment for this device
    prev = (
        db.query(Assessment)
        .filter(Assessment.device_id == device_id, Assessment.id != assessment.id)
        .order_by(Assessment.id.desc())
        .first()
    )
    if prev:
        prev_manuals = db.query(ManualFinding).filter(ManualFinding.assessment_id == prev.id).all()
        for mf in prev_manuals:
            db.add(ManualFinding(
                assessment_id=assessment.id,
                category=mf.category,
                question_key=mf.question_key,
                answer_value=mf.answer_value,
                comment=mf.comment,
                source=mf.source,
            ))
        if prev_manuals:
            db.commit()
            logger.info(f"Copied {len(prev_manuals)} manual findings from assessment {prev.id} to {assessment.id}")

    logger.info(f"Created assessment {assessment.id} for device {device_id}")
    return assessment


@router.get("/assessments/{assessment_id}", response_model=AssessmentRead)
def get_assessment(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    return _get_assessment_or_404(assessment_id, db)


@router.put("/assessments/{assessment_id}", response_model=AssessmentRead)
def update_assessment(
    assessment_id: int,
    body: AssessmentUpdate,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    a = _get_assessment_or_404(assessment_id, db)
    for k, v in body.model_dump(exclude_none=True).items():
        old = getattr(a, k, None)
        if old != v:
            db.add(AuditLog(assessment_id=a.id, user=user, action="field_updated", field_name=k, old_value=str(old), new_value=str(v)))
        setattr(a, k, v)
    db.commit()
    db.refresh(a)
    return a


# --- Scan Authorization ---

@router.post("/assessments/{assessment_id}/scan/authorize", response_model=ScanAuthorizationRead)
def create_scan_authorization(
    assessment_id: int,
    body: ScanAuthorizationCreate,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    a = _get_assessment_or_404(assessment_id, db)
    device = db.query(Device).filter(Device.id == a.device_id).first()
    existing = db.query(ScanAuthorization).filter(ScanAuthorization.assessment_id == assessment_id).first()
    if existing:
        db.delete(existing)
    auth = ScanAuthorization(
        assessment_id=assessment_id,
        authorized_by_name=body.authorized_by_name,
        authorized_by_role=body.authorized_by_role,
        authorized_by_contact=body.authorized_by_contact,
        authorization_date=datetime.now(timezone.utc),
        scan_profile=body.scan_profile,
        nmap_interface=body.nmap_interface or None,
        target_ip=device.ip_address,
        time_window_start=body.time_window_start,
        time_window_end=body.time_window_end,
        notes=body.notes,
        confirmed_by_user=user,
    )
    db.add(auth)
    db.commit()
    db.refresh(auth)
    return auth


@router.get("/assessments/{assessment_id}/scan/authorize", response_model=ScanAuthorizationRead)
def get_scan_authorization(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    auth = db.query(ScanAuthorization).filter(ScanAuthorization.assessment_id == assessment_id).first()
    if not auth:
        raise HTTPException(404, "Keine Autorisierung vorhanden")
    return auth


# --- Manual Findings ---

@router.get("/assessments/{assessment_id}/manual-findings")
def get_manual_findings(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    assessment = _get_assessment_or_404(assessment_id, db)
    existing = {
        mf.question_key: mf
        for mf in db.query(ManualFinding).filter(ManualFinding.assessment_id == assessment_id).all()
    }

    # Use scan_mode from DB (set at scan time); fall back to profile-name heuristic for old records
    scan_mode = getattr(assessment, "scan_mode", None) or "assessment"
    if scan_mode != "discovery":
        # Legacy fallback: check profile name
        # Only profiles that are explicitly discovery-only belong here.
        # "extended" and "version_deep" are full assessment profiles – NOT discovery.
        _LEGACY_DISCOVERY_PROFILES = {
            "r7_discovery_safe", "r7_light_discovery_ports",
        }
        if (assessment.scan_profile or "").lower() in _LEGACY_DISCOVERY_PROFILES:
            scan_mode = "discovery"

    result = {}
    category_enabled = {
        "nmos": bool(getattr(assessment, "manual_nmos_enabled", True)),
        "ptp_timing": bool(getattr(assessment, "manual_ptp_enabled", True)),
        "network_arch": bool(getattr(assessment, "manual_network_arch_enabled", True)),
    }
    for category, questions in QUESTION_CATALOG.items():
        if category in category_enabled and not category_enabled[category]:
            continue
        if scan_mode == "discovery":
            # Discovery mode: only show scan_effects questions
            if category != "scan_effects":
                continue
        else:
            # Assessment mode: skip scan_effects unless answers already saved
            if category == "scan_effects":
                has_answers = any(q["key"] in existing for q in questions)
                if not has_answers:
                    continue
        result[category] = [
            {
                "question_key": q["key"],
                "question": q["question"],
                "answer_value": existing.get(q["key"], ManualFinding()).answer_value,
                "comment": existing.get(q["key"], ManualFinding()).comment,
                "source": existing.get(q["key"], ManualFinding()).source,
            }
            for q in questions
        ]
    return result


@router.post("/assessments/{assessment_id}/manual-findings")
def save_manual_findings(
    assessment_id: int,
    body: List[ManualFindingCreate],
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    assessment = _get_assessment_or_404(assessment_id, db)
    enabled = {
        "nmos": bool(getattr(assessment, "manual_nmos_enabled", True)),
        "ptp_timing": bool(getattr(assessment, "manual_ptp_enabled", True)),
        "network_arch": bool(getattr(assessment, "manual_network_arch_enabled", True)),
    }
    disabled_categories = [cat for cat, is_on in enabled.items() if not is_on]
    if disabled_categories:
        db.query(ManualFinding).filter(
            ManualFinding.assessment_id == assessment_id,
            ManualFinding.category.in_(disabled_categories),
        ).delete(synchronize_session=False)
    for item in body:
        if item.category in enabled and not enabled[item.category]:
            continue
        existing = db.query(ManualFinding).filter(
            ManualFinding.assessment_id == assessment_id,
            ManualFinding.question_key == item.question_key,
        ).first()
        if existing:
            existing.answer_value = item.answer_value
            existing.comment = item.comment
            existing.source = item.source
        else:
            db.add(ManualFinding(
                assessment_id=assessment_id,
                category=item.category,
                question_key=item.question_key,
                answer_value=item.answer_value,
                comment=item.comment,
                source=item.source,
            ))
    db.commit()
    return {"saved": len(body)}


# --- Findings ---

@router.get("/assessments/{assessment_id}/findings", response_model=List[FindingRead])
def get_findings(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    _get_assessment_or_404(assessment_id, db)
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    result = []
    for f in findings:
        fr = FindingRead.model_validate(f)
        if f.cve_id:
            cc = (
                db.query(CveCache)
                .filter(CveCache.cve_id == f.cve_id)
                .order_by(CveCache.fetched_at.desc())
                .first()
            )
            if cc:
                fr.cve_fetched_at = cc.fetched_at
        result.append(fr)
    return result


@router.put("/assessments/{assessment_id}/findings/{finding_id}", response_model=FindingRead)
def update_finding(
    assessment_id: int,
    finding_id: int,
    body: FindingUpdate,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    finding = db.query(Finding).filter(Finding.id == finding_id, Finding.assessment_id == assessment_id).first()
    if not finding:
        raise HTTPException(404, "Finding nicht gefunden")
    for k, v in body.model_dump(exclude_none=True).items():
        old = getattr(finding, k)
        if old != v:
            db.add(AuditLog(assessment_id=assessment_id, user=user, action="finding_status_changed",
                            field_name=k, old_value=str(old), new_value=str(v)))
        setattr(finding, k, v)
    db.commit()
    db.refresh(finding)
    return finding


# --- Recalculate ---

@router.post("/assessments/{assessment_id}/recalculate")
def recalculate_scores(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    a = _get_assessment_or_404(assessment_id, db)
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    result = scoring_service.recalculate(findings)
    a.technical_score = result["technical"]
    a.operational_score = result["operational"]
    a.compensation_score = result["compensation"]
    a.lifecycle_score = result["lifecycle"]
    a.vendor_score = result["vendor"]
    a.overall_rating = result["overall_rating"]
    db.commit()
    db.refresh(a)
    return result


@router.get("/assessments/{assessment_id}/scoring-details")
def get_scoring_details(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    """Return detailed scoring breakdown with per-dimension reasons for UI transparency panel."""
    _get_assessment_or_404(assessment_id, db)
    findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
    result = scoring_service.recalculate_detailed(findings)

    # Serialize dataclasses to JSON-compatible dict
    dims = {}
    for dim, ds in result.dimensions.items():
        dims[dim] = {
            "dimension": ds.dimension,
            "score": ds.score,
            "max_score": ds.max_score,
            "standard_ref": ds.standard_ref,
            "reasons": [
                {"type": r.type, "text": r.text, "impact": r.impact,
                 "finding_id": r.finding_id, "rule_key": r.rule_key}
                for r in ds.reasons
            ],
        }
    return {
        "overall_rating": result.overall_rating,
        "overall_score": result.overall_score,
        "dimensions": dims,
        "override_reasons": result.override_reasons,
        "decision_path": result.decision_path,
    }


# --- Vendor Information ---

@router.get("/assessments/{assessment_id}/vendor-info", response_model=VendorInfoRead)
def get_vendor_info(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    vi = db.query(VendorInformation).filter(VendorInformation.assessment_id == assessment_id).first()
    if not vi:
        raise HTTPException(404, "Keine Hersteller-Information vorhanden")
    return vi


@router.put("/assessments/{assessment_id}/vendor-info", response_model=VendorInfoRead)
def upsert_vendor_info(
    assessment_id: int,
    body: VendorInfoCreate,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    _get_assessment_or_404(assessment_id, db)
    vi = db.query(VendorInformation).filter(VendorInformation.assessment_id == assessment_id).first()
    if vi:
        for k, v in body.model_dump(exclude_none=True).items():
            setattr(vi, k, v)
    else:
        vi = VendorInformation(assessment_id=assessment_id, **body.model_dump())
        db.add(vi)
    db.commit()
    db.refresh(vi)
    return vi


# --- Action Items ---

@router.get("/assessments/{assessment_id}/action-items", response_model=List[ActionItemRead])
def get_action_items(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    _get_assessment_or_404(assessment_id, db)
    return db.query(ActionItem).filter(ActionItem.assessment_id == assessment_id).all()


@router.post("/assessments/{assessment_id}/action-items", response_model=ActionItemRead, status_code=201)
def create_action_item(
    assessment_id: int,
    body: ActionItemCreate,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    _get_assessment_or_404(assessment_id, db)
    item = ActionItem(assessment_id=assessment_id, **body.model_dump())
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


@router.get("/devices/{device_id}/assessments", response_model=List[AssessmentRead])
def list_device_assessments(
    device_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """List all assessments for a device, newest first."""
    device = db.query(Device).filter(Device.id == device_id).first()
    if not device:
        raise HTTPException(404, "Gerät nicht gefunden")
    return (
        db.query(Assessment)
        .filter(Assessment.device_id == device_id)
        .order_by(Assessment.created_at.desc())
        .all()
    )


@router.post("/assessments/{assessment_id}/clone", status_code=201)
def clone_assessment(
    assessment_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """Create a new draft assessment for the same device, copying scan profile,
    reviewer, manual answers (as template) and compensating control descriptions."""
    src = _get_assessment_or_404(assessment_id, db)
    new_a = Assessment(
        device_id=src.device_id,
        status="draft",
        scan_profile=src.scan_profile,
        reviewer=src.reviewer,
        manual_nmos_enabled=src.manual_nmos_enabled,
        manual_ptp_enabled=src.manual_ptp_enabled,
        manual_network_arch_enabled=src.manual_network_arch_enabled,
    )
    db.add(new_a)
    db.flush()  # get new_a.id

    # Copy manual findings as template (answers + comments)
    src_mf = db.query(ManualFinding).filter(ManualFinding.assessment_id == assessment_id).all()
    for mf in src_mf:
        db.add(ManualFinding(
            assessment_id=new_a.id,
            category=mf.category,
            question_key=mf.question_key,
            answer_value=mf.answer_value,
            comment=mf.comment,
            source=mf.source,
        ))

    db.commit()
    db.refresh(new_a)
    return {"new_assessment_id": new_a.id}


@router.delete("/assessments/{assessment_id}", status_code=204)
def delete_assessment(
    assessment_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """Delete an assessment and all its related data."""
    assessment = _get_assessment_or_404(assessment_id, db)
    for model in (ScanResult, Finding, ManualFinding, ScanAuthorization,
                  VendorInformation, ActionItem, AuditLog):
        db.query(model).filter(model.assessment_id == assessment_id).delete()
    db.delete(assessment)
    db.commit()
