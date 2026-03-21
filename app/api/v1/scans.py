import asyncio
import logging
from typing import List

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from app.core.database import get_db, SessionLocal
from app.core.security import verify_credentials
from app.models.assessment import Assessment
from app.models.device import Device
from app.models.finding import Finding
from app.models.scan_result import ScanResult
from app.schemas.scan import ScanResultRead, ScanStatusRead
from app.services import nmap_service, rule_engine, scoring_service
from app.core.config import settings

logger = logging.getLogger("pibroadguard.scan")
router = APIRouter(tags=["scans"])

_scan_status: dict = {}


async def _run_scan_task(assessment_id: int, ip: str, profile: str):
    _scan_status[assessment_id] = {"status": "running", "message": "Scan läuft..."}
    db = SessionLocal()
    try:
        result = await nmap_service.run_scan(
            ip, profile,
            host_timeout=settings.pibg_nmap_host_timeout,
            max_rate=settings.pibg_nmap_max_rate,
        )
        assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if not assessment:
            return

        # Save scan results
        raw_xml = result.get("xml", "")
        for sr_data in result.get("results", []):
            sr = ScanResult(
                assessment_id=assessment_id,
                port=sr_data["port"],
                protocol=sr_data["protocol"],
                service_name=sr_data["service_name"],
                service_product=sr_data["service_product"],
                service_version=sr_data["service_version"],
                state=sr_data["state"],
                extra_info=sr_data["extra_info"],
                raw_nmap_output=raw_xml,
            )
            db.add(sr)
        db.commit()

        # Apply rules
        rules = rule_engine.load_rules()
        manual_answers = {}
        triggered = rule_engine.apply_rules(rules, result.get("results", []), manual_answers)

        for t in triggered:
            finding = Finding(
                assessment_id=assessment_id,
                rule_key=t["rule_key"],
                title=t["title"],
                severity=t["severity"],
                description=t["description"],
                evidence=t["evidence"],
                recommendation=t["recommendation"],
                broadcast_context=t["broadcast_context"],
                compensating_control_required=t["compensating_control_required"],
                status="open",
            )
            db.add(finding)
        db.commit()

        # Recalculate scores
        findings = db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
        scores = scoring_service.recalculate(triggered)
        assessment.technical_score = scores["technical"]
        assessment.operational_score = scores["operational"]
        assessment.compensation_score = scores["compensation"]
        assessment.lifecycle_score = scores["lifecycle"]
        assessment.vendor_score = scores["vendor"]
        assessment.overall_rating = scores["overall_rating"]
        assessment.status = "scan_complete"
        db.commit()

        _scan_status[assessment_id] = {
            "status": "complete",
            "message": f"Scan abgeschlossen. {len(result.get('results', []))} offene Ports, {len(triggered)} Findings.",
            "port_count": len(result.get("results", [])),
        }
        logger.info(f"Scan {assessment_id} complete: {len(triggered)} findings")

    except Exception as e:
        logger.error(f"Scan {assessment_id} failed: {e}")
        db_a = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if db_a:
            db_a.status = "draft"
            db.commit()
        _scan_status[assessment_id] = {"status": "error", "message": str(e)}
    finally:
        db.close()


@router.post("/assessments/{assessment_id}/scan")
def start_scan(
    assessment_id: int,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")
    if assessment.status == "scan_running":
        raise HTTPException(409, "Scan läuft bereits")

    # Check authorization exists
    from app.models.scan_authorization import ScanAuthorization
    auth = db.query(ScanAuthorization).filter(ScanAuthorization.assessment_id == assessment_id).first()
    if not auth:
        raise HTTPException(400, "Scan-Autorisierung erforderlich – zuerst autorisieren")

    device = db.query(Device).filter(Device.id == assessment.device_id).first()
    assessment.status = "scan_running"
    db.commit()

    background_tasks.add_task(
        asyncio.run,
        _run_scan_task(assessment_id, device.ip_address, assessment.scan_profile or "passive"),
    )
    return {"message": "Scan gestartet", "assessment_id": assessment_id}


@router.get("/assessments/{assessment_id}/scan/status", response_model=ScanStatusRead)
def get_scan_status(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")
    status = _scan_status.get(assessment_id, {"status": assessment.status, "message": ""})
    return ScanStatusRead(
        status=status.get("status", assessment.status),
        message=status.get("message"),
        port_count=status.get("port_count"),
        scan_profile=assessment.scan_profile,
    )


@router.get("/assessments/{assessment_id}/scan/results", response_model=List[ScanResultRead])
def get_scan_results(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")
    return db.query(ScanResult).filter(ScanResult.assessment_id == assessment_id).all()
