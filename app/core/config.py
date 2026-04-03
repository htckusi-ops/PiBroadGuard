import os
from pydantic_settings import BaseSettings
from pydantic import field_validator


class Settings(BaseSettings):
    # Auth
    pibg_username: str = "admin"
    pibg_password: str = "changeme"

    # Database
    pibg_db_path: str = "./data/pibroadguard.db"

    # Rules
    pibg_rules_path: str = "./app/rules/default_rules.yaml"

    # Logging
    pibg_log_level: str = "INFO"
    pibg_log_path: str = "./data/logs/pibroadguard.log"

    # Connectivity
    pibg_initial_connectivity_mode: str = "auto"
    pibg_connectivity_check_url: str = "https://nvd.nist.gov"
    pibg_connectivity_timeout: int = 5

    # CVE / KEV
    pibg_nvd_api_key: str = ""
    pibg_cve_cache_ttl_days: int = 7
    pibg_kev_sync_interval_hours: int = 24

    # Encryption
    pibg_shared_secret: str = ""
    pibg_encryption_enabled: bool = True

    # Backup
    pibg_backup_max_count: int = 5

    # Nmap
    pibg_nmap_host_timeout: str = "300s"
    pibg_nmap_max_rate: int = 100

    # Scan Queue
    pibg_max_parallel_scans: int = 1

    # Scheduler
    pibg_scheduler_timezone: str = "Europe/Zurich"

    # phpIPAM
    pibg_phpipam_url: str = ""
    pibg_phpipam_app_id: str = "pibroadguard"
    pibg_phpipam_token: str = ""
    
    # CORS
    pibg_cors_origins: str = "http://localhost,http://127.0.0.1"

    @property
    def database_url(self) -> str:
        return f"sqlite:///{self.pibg_db_path}"

    @property
    def username(self) -> str:
        return self.pibg_username

    @property
    def password(self) -> str:
        return self.pibg_password
    
    @property
    def cors_origins(self) -> list[str]:
        raw = self.pibg_cors_origins or ""
        return [o.strip() for o in raw.split(",") if o.strip()]

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()
