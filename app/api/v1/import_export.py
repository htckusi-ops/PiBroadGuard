import logging
from fastapi import APIRouter, Depends, File, HTTPException, Response, UploadFile
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import verify_credentials
from app.models.assessment import Assessment
from app.services import package_service

logger = logging.getLogger("pibroadguard.import")
router = APIRouter(tags=["import_export"])


@router.get("/assessments/{assessment_id}/export")
def export_assessment(
    assessment_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")
    if assessment.status not in ("scan_complete", "exported", "completed"):
        raise HTTPException(400, "Assessment hat keinen abgeschlossenen Scan")
    try:
        data = package_service.export_package(db, assessment_id)
    except Exception as e:
        raise HTTPException(500, str(e))

    assessment.status = "exported"
    db.commit()

    filename = f"assessment-{assessment_id}.bdsa"
    return Response(
        content=data,
        media_type="application/octet-stream",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.get("/assessments/{assessment_id}/export/verify")
def verify_export_meta(
    assessment_id: int,
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    assessment = db.query(Assessment).filter(Assessment.id == assessment_id).first()
    if not assessment:
        raise HTTPException(404, "Assessment nicht gefunden")
    return {
        "assessment_id": assessment_id,
        "status": assessment.status,
        "exportable": assessment.status in ("scan_complete", "exported", "completed"),
    }


@router.post("/import")
async def import_package(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: str = Depends(verify_credentials),
):
    data = await file.read()
    try:
        result = package_service.import_package(db, data, user)
        return result
    except ValueError as e:
        raise HTTPException(400, str(e))
    except Exception as e:
        logger.error(f"Import failed: {e}")
        raise HTTPException(500, str(e))


@router.post("/import/verify")
async def verify_package(
    file: UploadFile = File(...),
    user: str = Depends(verify_credentials),
):
    data = await file.read()
    return package_service.verify_package(data)


@router.get("/import/history")
def import_history(db: Session = Depends(get_db), user: str = Depends(verify_credentials)):
    from app.models.import_log import ImportLog
    logs = db.query(ImportLog).order_by(ImportLog.imported_at.desc()).limit(50).all()
    return [
        {
            "id": l.id,
            "package_id": l.package_id,
            "assessment_id": l.assessment_id,
            "imported_at": l.imported_at.isoformat() if l.imported_at else None,
            "imported_by": l.imported_by,
            "source_host": l.source_host,
            "status": l.status,
            "error_message": l.error_message,
        }
        for l in logs
    ]
