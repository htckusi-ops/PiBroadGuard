from typing import Optional
from datetime import datetime
from pydantic import BaseModel, field_validator
import ipaddress


class DeviceBase(BaseModel):
    manufacturer: str
    model: str
    device_type: str
    serial_number: Optional[str] = None
    asset_tag: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: str
    firmware_version: Optional[str] = None
    location: Optional[str] = None
    network_segment: Optional[str] = None
    production_criticality: Optional[str] = None
    owner_team: Optional[str] = None
    notes: Optional[str] = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        ipaddress.ip_address(v)
        return v


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(DeviceBase):
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    device_type: Optional[str] = None
    ip_address: Optional[str] = None

    @field_validator("ip_address", mode="before")
    @classmethod
    def validate_ip_optional(cls, v):
        if v is not None:
            ipaddress.ip_address(v)
        return v


class DeviceRead(DeviceBase):
    id: int
    deleted: bool
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_assessment_status: Optional[str] = None
    last_assessment_rating: Optional[str] = None
    last_assessment_id: Optional[int] = None
    last_assessment_date: Optional[datetime] = None

    model_config = {"from_attributes": True}
