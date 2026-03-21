from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class ScanResultRead(BaseModel):
    id: int
    assessment_id: int
    port: Optional[int] = None
    protocol: Optional[str] = None
    service_name: Optional[str] = None
    service_product: Optional[str] = None
    service_version: Optional[str] = None
    state: Optional[str] = None
    extra_info: Optional[str] = None
    scanned_at: Optional[datetime] = None

    model_config = {"from_attributes": True}


class ScanStatusRead(BaseModel):
    status: str
    message: Optional[str] = None
    port_count: Optional[int] = None
    scan_profile: Optional[str] = None
