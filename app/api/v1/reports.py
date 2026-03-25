import logging
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_credentials
from app.models.assessment import Assessment
from app.services import report_service

try:
    import weasyprint as _weasyprint
    _PDF_AVAILABLE = True
except Exception:
    _PDF_AVAILABLE = False

logger = logging.getLogger("pibroadguard.api")
router = APIRouter(tags=["reports"])


@router.get("/assessments/{assessment_id}/report/md")
def get_report_md(assessment_id: int, db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")
    content = report_service.generate_markdown(db, assessment)
    return Response(content=content, media_type="text/markdown", headers={
        "Content-Disposition": f'attachment; filename="report-{assessment_id}.md"'
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
    return Response(content=content, media_type="application/json", headers={
        "Content-Disposition": f'attachment; filename="report-{assessment_id}.json"'
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
    device = assessment.device if hasattr(assessment, "device") else None
    filename = f"report-{assessment_id}.pdf"
    return Response(
        content=pdf_bytes,
        media_type="application/pdf",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
