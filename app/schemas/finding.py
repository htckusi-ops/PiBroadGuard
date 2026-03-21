from typing import Optional
from datetime import datetime
from pydantic import BaseModel


class FindingRead(BaseModel):
    id: int
    assessment_id: int
    rule_key: Optional[str] = None
    title: Optional[str] = None
    severity: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    recommendation: Optional[str] = None
    broadcast_context: Optional[str] = None
    compensating_control_required: bool = False
    compensating_control_description: Optional[str] = None
    status: str = "open"
    cve_id: Optional[str] = None
    cvss_score: Optional[str] = None
    cwe_id: Optional[str] = None
    kev_listed: bool = False
    kev_required_action: Optional[str] = None
    nvd_solution: Optional[str] = None
    vendor_advisory_url: Optional[str] = None
    cwe_recommendation: Optional[str] = None
    created_at: Optional[datetime] = None

    model_config = {"from_attributes": True}
