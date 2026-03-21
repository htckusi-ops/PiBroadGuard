from typing import Optional, List
from datetime import datetime
from pydantic import BaseModel


class ConnectivityModeUpdate(BaseModel):
    mode: str  # auto | force_online | force_offline


class ConnectivityStatus(BaseModel):
    mode_setting: str
    auto_detected: Optional[bool] = None
    effective_mode: str
    last_check: Optional[datetime] = None
    nvd_reachable: bool = False
    kev_cache_age_hours: Optional[float] = None
    override_active: bool = False


class BackupCreate(BaseModel):
    destination: str = "local"
    usb_path: Optional[str] = None
    encrypt: bool = False


class BackupInfo(BaseModel):
    filename: str
    size_bytes: int
    created_at: datetime
    encrypted: bool


class UsbDevice(BaseModel):
    path: str
    label: str
    filesystem: str
    free_bytes: int
    total_bytes: int
    writable: bool


class UsbExportRequest(BaseModel):
    target_path: str
    export_type: str = "single"
    assessment_ids: Optional[List[int]] = None
    encrypt: bool = True
    include_raw: bool = True


class UsbImportRequest(BaseModel):
    source_path: str
    filenames: List[str]
