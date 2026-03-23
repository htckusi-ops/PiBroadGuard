import asyncio
import logging
from typing import AsyncGenerator, List
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from app.core.database import get_db, SessionLocal
from app.core.security import verify_credentials
from app.models.assessment import Assessment
from app.models.device import Device
from app.models.finding import Finding
from app.models.scan_result import ScanResult
from app.schemas.scan import ScanResultRead, ScanStatusRead
from app.services import nmap_service, rule_engine, scoring_service
from app.services.nmap_service import scan_queues
from app.core.config import settings

logger = logging.getLogger("pibroadguard.scan")
router = APIRouter(tags=["scans"])

_scan_status: dict = {}
_job_id_for_assessment: dict = {}  # assessment_id -> job_id


async def _run_scan_task(assessment_id: int, ip: str, profile: str):
    _scan_status[assessment_id] = {"status": "running", "message": "Scan läuft..."}
    db = SessionLocal()
    try:
        # Load profile flags from DB (supports custom profiles), fall back to built-in
        flags_override = None
        timeout_override = None
        try:
            from app.models.scan_profile import ScanProfile
            import json as _json
            sp = db.query(ScanProfile).filter(
                ScanProfile.name == profile, ScanProfile.active == True
            ).first()
            if sp:
                flags_override = _json.loads(sp.nmap_flags)
                timeout_override = sp.timeout_seconds
        except Exception:
            pass

        result = await nmap_service.run_scan(
            ip, profile,
            host_timeout=settings.pibg_nmap_host_timeout,
            max_rate=settings.pibg_nmap_max_rate,
            assessment_id=assessment_id,
            flags_override=flags_override,
            timeout_override=timeout_override,
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
                remediation_sources=t.get("remediation_sources"),
                status="open",
            )
            db.add(finding)
        db.commit()

        # Auto CVE lookup: for any service with a detected product+version
        # create CVSS-based findings when online.
        cve_findings_added = 0
        try:
            from app.services import connectivity_service, cve_service
            from app.models.system_settings import SystemSettings
            mode_row = db.query(SystemSettings).filter(SystemSettings.key == "connectivity_mode").first()
            conn_mode = mode_row.value if mode_row else "auto"
            if connectivity_service.is_online(conn_mode):
                seen_cves: set = set()
                for sr_data in result.get("results", []):
                    product = sr_data.get("service_product", "").strip()
                    version = sr_data.get("service_version", "").strip()
                    if not product:
                        continue
                    cves = await cve_service.lookup_cves(
                        db, vendor=product, product=product, version=version
                    )
                    for cve in cves:
                        cve_id = cve.get("cve_id", "")
                        if not cve_id or cve_id in seen_cves:
                            continue
                        cvss = float(cve.get("cvss_score") or 0.0)
                        if cvss <= 0:
                            continue
                        seen_cves.add(cve_id)
                        if cvss >= 9.0:
                            sev = "critical"
                        elif cvss >= 7.0:
                            sev = "high"
                        elif cvss >= 4.0:
                            sev = "medium"
                        else:
                            sev = "low"
                        ver_str = f" {version}" if version else ""
                        f = Finding(
                            assessment_id=assessment_id,
                            rule_key=f"cve_{cve_id.lower().replace('-', '_')}",
                            title=f"{cve_id} – {product}{ver_str} (CVSS {cvss:.1f})",
                            severity=sev,
                            description=cve.get("description", ""),
                            evidence=f"Port {sr_data['port']}/{sr_data['protocol']}: {product}{ver_str}",
                            recommendation=cve.get("nvd_solution") or f"Update {product} auf eine gepatchte Version.",
                            broadcast_context="CVE in erkannter Softwareversion auf Broadcast-Gerät – Patch-Status prüfen.",
                            compensating_control_required=(cvss >= 7.0),
                            status="open",
                        )
                        db.add(f)
                        cve_findings_added += 1
                if cve_findings_added:
                    db.commit()
                    # Re-read all findings (incl. CVE ones) for accurate scoring
                    triggered_all = [
                        {
                            "severity": fi.severity,
                            "affects_score": "technical",
                            "status": fi.status,
                            "compensating_control_description": fi.compensating_control_description,
                        }
                        for fi in db.query(Finding).filter(Finding.assessment_id == assessment_id).all()
                    ]
                    triggered = triggered_all
        except Exception as cve_err:
            logger.warning(f"CVE auto-lookup failed (non-fatal): {cve_err}")

        # Recalculate scores
        scores = scoring_service.recalculate(triggered)
        assessment.technical_score = scores["technical"]
        assessment.operational_score = scores["operational"]
        assessment.compensation_score = scores["compensation"]
        assessment.lifecycle_score = scores["lifecycle"]
        assessment.vendor_score = scores["vendor"]
        assessment.overall_rating = scores["overall_rating"]
        assessment.status = "scan_complete"
        db.commit()

        port_count = len(result.get("results", []))
        cve_note = f", {cve_findings_added} CVE-Findings" if cve_findings_added else ""
        _scan_status[assessment_id] = {
            "status": "complete",
            "message": f"Scan abgeschlossen. {port_count} offene Ports, {len(triggered)} Findings{cve_note}.",
            "port_count": port_count,
            "elapsed_seconds": result.get("elapsed_seconds"),
            "nmap_version": result.get("nmap_version"),
        }
        logger.info(f"Scan {assessment_id} complete: {len(triggered)} findings")

    except Exception as e:
        logger.error(f"Scan {assessment_id} failed: {e}")
        db_a = db.query(Assessment).filter(Assessment.id == assessment_id).first()
        if db_a:
            db_a.status = "draft"
            db.commit()
        _scan_status[assessment_id] = {"status": "error", "message": str(e)}
        # Signal SSE clients of error
        q = scan_queues.get(assessment_id)
        if q:
            await q.put(f"data: FEHLER: {e}\n\ndata: __DONE__\n\n")
    finally:
        db.close()


@router.post("/assessments/{assessment_id}/scan")
async def start_scan(
    assessment_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    from app.services.scan_queue_service import get_queue, ScanJob

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

    queue = get_queue()
    if not queue:
        # Fallback: direct background execution (should not happen in normal ops)
        assessment.status = "scan_running"
        db.commit()
        asyncio.create_task(_run_scan_task(
            assessment_id, device.ip_address, assessment.scan_profile or "passive"
        ))
        return {"message": "Scan gestartet (direkt)", "assessment_id": assessment_id, "job_id": None}

    job_id = f"manual_{assessment_id}_{uuid4().hex[:6]}"
    job = ScanJob(
        job_id=job_id,
        assessment_id=assessment_id,
        device_id=assessment.device_id,
        ip_address=device.ip_address,
        scan_profile=assessment.scan_profile or "passive",
        triggered_by="manual",
    )
    result = await queue.enqueue(job)

    if result.status.value == "skipped":
        raise HTTPException(409, "Gerät wird bereits gescannt oder befindet sich in der Queue")

    # Mark assessment as scan_running now so UI reflects it immediately
    assessment.status = "scan_running"
    db.commit()
    _job_id_for_assessment[assessment_id] = job_id

    return {
        "message": "Scan in Queue eingereiht",
        "assessment_id": assessment_id,
        "job_id": job_id,
        "position": result.position,
    }


# ── Scan Queue Endpoints ───────────────────────────────────────────────────

@router.get("/scan-queue/status")
def get_queue_status(user: str = Depends(verify_credentials)):
    from app.services.scan_queue_service import get_queue
    queue = get_queue()
    if not queue:
        return {"queued": [], "running": [], "history": [], "max_parallel": 1}
    return queue.get_status()


@router.delete("/scan-queue/{job_id}", status_code=200)
async def cancel_queue_job(job_id: str, user: str = Depends(verify_credentials)):
    from app.services.scan_queue_service import get_queue
    queue = get_queue()
    if not queue:
        raise HTTPException(503, "Queue nicht verfügbar")
    cancelled = await queue.cancel(job_id)
    if not cancelled:
        raise HTTPException(404, "Job nicht in Queue (läuft bereits oder existiert nicht)")
    return {"cancelled": True, "job_id": job_id}


@router.get("/assessments/{assessment_id}/scan/stream")
async def stream_scan_output(
    assessment_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    """SSE endpoint streaming live nmap output for a running scan."""
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")

    async def event_generator() -> AsyncGenerator[str, None]:
        # Wait up to 5s for queue to appear (scan may start slightly after)
        for _ in range(50):
            if assessment_id in scan_queues:
                break
            await asyncio.sleep(0.1)

        queue = scan_queues.get(assessment_id)
        if queue is None:
            yield "data: Kein aktiver Scan gefunden\n\ndata: __DONE__\n\n"
            return

        while True:
            try:
                msg = await asyncio.wait_for(queue.get(), timeout=30.0)
                yield msg
                if "__DONE__" in msg:
                    scan_queues.pop(assessment_id, None)
                    break
            except asyncio.TimeoutError:
                yield "data: keepalive\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.get("/assessments/{assessment_id}/scan/status", response_model=ScanStatusRead)
def get_scan_status(
    assessment_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
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
def get_scan_results(
    assessment_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")
    return db.query(ScanResult).filter(ScanResult.assessment_id == assessment_id).all()
