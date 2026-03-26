from typing import Optional, List
from datetime import datetime, date
from pydantic import BaseModel


class AssessmentCreate(BaseModel):
    scan_profile: str = "passive"


class AssessmentUpdate(BaseModel):
    status: Optional[str] = None
    reviewer: Optional[str] = None
    summary: Optional[str] = None
    decision: Optional[str] = None
    decision_notes: Optional[str] = None
    reassessment_due: Optional[date] = None


class AssessmentRead(BaseModel):
    id: int
    device_id: int
    status: str
    scan_profile: Optional[str] = None
    scan_mode: Optional[str] = "assessment"
    overall_rating: Optional[str] = None
    technical_score: int
    operational_score: int
    compensation_score: int
    lifecycle_score: int
    vendor_score: int
    reviewer: Optional[str] = None
    summary: Optional[str] = None
    decision: Optional[str] = None
    decision_notes: Optional[str] = None
    reassessment_due: Optional[date] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ScanAuthorizationCreate(BaseModel):
    authorized_by_name: str
    authorized_by_role: str
    authorized_by_contact: Optional[str] = None
    scan_profile: str
    nmap_interface: Optional[str] = None  # None / "auto" = let nmap decide
    time_window_start: Optional[datetime] = None
    time_window_end: Optional[datetime] = None
    notes: Optional[str] = None


class ScanAuthorizationRead(ScanAuthorizationCreate):
    id: int
    assessment_id: int
    authorization_date: datetime
    target_ip: str
    confirmed_by_user: str
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ManualFindingCreate(BaseModel):
    category: str
    question_key: str
    answer_value: str
    comment: Optional[str] = None
    source: Optional[str] = None


class ManualFindingRead(ManualFindingCreate):
    id: int
    assessment_id: int

    model_config = {"from_attributes": True}


class VendorInfoCreate(BaseModel):
    support_end_date: Optional[date] = None
    security_update_policy: Optional[str] = None
    psirt_available: Optional[bool] = None
    advisory_process: Optional[str] = None
    hardening_guide: Optional[bool] = None
    security_contact: Optional[str] = None
    notes: Optional[str] = None
    source_reference: Optional[str] = None


class VendorInfoRead(VendorInfoCreate):
    id: int
    assessment_id: int

    model_config = {"from_attributes": True}


class ActionItemCreate(BaseModel):
    title: str
    description: Optional[str] = None
    responsible_team: Optional[str] = None
    priority: str = "short_term"
    due_date: Optional[date] = None
    finding_id: Optional[int] = None


class ActionItemRead(ActionItemCreate):
    id: int
    assessment_id: int
    status: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    compensating_control_description: Optional[str] = None
    compensating_control_required: Optional[bool] = None
