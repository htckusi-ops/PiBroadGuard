import logging
from fastapi import APIRouter, Depends, HTTPException, Response
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_credentials
from app.models.assessment import Assessment
from app.services import report_service

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
