from typing import Optional
from datetime import datetime
from pydantic import BaseModel, Field, field_validator
import ipaddress


class DeviceBase(BaseModel):
    manufacturer: str
    model: str
    device_type: str
    device_class_id: Optional[int] = None
    serial_number: Optional[str] = None
    asset_tag: Optional[str] = None
    hostname: Optional[str] = None
    ip_address: str
    firmware_version: Optional[str] = None
    operating_system: Optional[str] = None
    location: Optional[str] = None
    network_segment: Optional[str] = None
    production_criticality: Optional[str] = None
    owner_team: Optional[str] = None
    notes: Optional[str] = None
    device_capabilities: Optional[list[str]] = None
    nmos_registry_url: Optional[str] = None
    nmos_node_api_url: Optional[str] = None
    nmos_connection_api_url: Optional[str] = None
    ping_monitor_enabled: Optional[bool] = None
    ping_interval_minutes: Optional[int] = None

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        ipaddress.ip_address(v)
        return v

    @field_validator("ping_interval_minutes")
    @classmethod
    def validate_ping_interval(cls, v):
        if v is None:
            return v
        if int(v) < 1:
            raise ValueError("ping_interval_minutes must be >= 1")
        return int(v)


class DeviceCreate(DeviceBase):
    pass


class DeviceUpdate(DeviceBase):
    manufacturer: Optional[str] = None
    model: Optional[str] = None
    device_type: Optional[str] = None
    device_class_id: Optional[int] = None
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
    device_class_id: Optional[int] = None
    rdns_hostname: Optional[str] = None
    mac_address: Optional[str] = None
    mac_vendor: Optional[str] = None
    phpipam_id: Optional[int] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    last_assessment_status: Optional[str] = None
    last_assessment_rating: Optional[str] = None
    last_assessment_id: Optional[int] = None
    last_assessment_date: Optional[datetime] = None
    last_ping_status: Optional[str] = None
    last_ping_checked_at: Optional[datetime] = None
    last_seen_ping_at: Optional[datetime] = None
    last_ping_rtt_ms: Optional[int] = None
    device_capabilities: list[str] = Field(default_factory=list)

    model_config = {"from_attributes": True}
