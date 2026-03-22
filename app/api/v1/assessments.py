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
    assessment = Assessment(device_id=device_id, scan_profile=body.scan_profile, status="draft")
    db.add(assessment)
    db.commit()
    db.refresh(assessment)
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
    _get_assessment_or_404(assessment_id, db)
    existing = {
        mf.question_key: mf
        for mf in db.query(ManualFinding).filter(ManualFinding.assessment_id == assessment_id).all()
    }
    result = {}
    for category, questions in QUESTION_CATALOG.items():
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
    _get_assessment_or_404(assessment_id, db)
    for item in body:
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
    return db.query(Finding).filter(Finding.assessment_id == assessment_id).all()


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
