import logging
import re
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_credentials
from app.models.assessment import Assessment
from app.services import report_service

logger = logging.getLogger("pibroadguard.api")

try:
    import weasyprint as _weasyprint
    _PDF_AVAILABLE = True
    logger.debug("weasyprint loaded successfully")
except Exception as _pdf_import_err:
    _PDF_AVAILABLE = False
    _pdf_import_msg = str(_pdf_import_err)
    logger.warning(f"weasyprint not available – PDF export disabled: {_pdf_import_err}")

router = APIRouter(tags=["reports"])

_SAFE = re.compile(r"[^A-Za-z0-9_-]")


def _report_stem(assessment: Assessment) -> str:
    """Build a descriptive filename stem without extension.

    Format: pibroadguard-YYYYMMDD-{manufacturer}-{model}-a{id}
    Example: pibroadguard-20260329-GrassValley-AMPPNode-a17
    """
    date_str = (assessment.created_at or datetime.now(timezone.utc)).strftime("%Y%m%d")
    device = getattr(assessment, "device", None)
    mfr = _SAFE.sub("", (getattr(device, "manufacturer", "") or "").replace(" ", ""))[:20]
    model = _SAFE.sub("", (getattr(device, "model", "") or "").replace(" ", ""))[:20]
    parts = ["pibroadguard", date_str]
    if mfr:
        parts.append(mfr)
    if model:
        parts.append(model)
    parts.append(f"a{assessment.id}")
    return "-".join(parts)


@router.get("/assessments/{assessment_id}/report/md")
def get_report_md(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")
    content = report_service.generate_markdown(db, assessment)
    filename = f"{_report_stem(assessment)}.md"
    return Response(content=content, media_type="text/markdown", headers={
        "Content-Disposition": f'attachment; filename="{filename}"'
    })


@router.get("/assessments/{assessment_id}/report/html")
def get_report_html(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")
    content = report_service.generate_html(db, assessment)
    return Response(content=content, media_type="text/html")


@router.get("/assessments/{assessment_id}/report/json")
def get_report_json(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")
    content = report_service.generate_json(db, assessment)
    filename = f"{_report_stem(assessment)}.json"
    return Response(content=content, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="{filename}"'
    })


@router.get("/assessments/{assessment_id}/report/pdf")
def get_report_pdf(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    if not _PDF_AVAILABLE:
        raise HTTPException(503, "PDF-Export nicht verfügbar (weasyprint nicht installiert)")
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")
    html_content = report_service.generate_html(db, assessment)
    try:
        pdf_bytes = _weasyprint.HTML(string=html_content).write_pdf()
    except Exception as exc:
        logger.error(f"PDF generation failed for assessment {assessment_id}: {exc}")
        raise HTTPException(500, f"PDF-Generierung fehlgeschlagen: {exc}")
    filename = f"{_report_stem(assessment)}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
