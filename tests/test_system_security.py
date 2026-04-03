import pytest
from fastapi import HTTPException

from app.api.v1 import system


def test_download_backup_rejects_path_traversal():
    with pytest.raises(HTTPException) as exc:
        system.download_backup("../secret.txt", db=None, user="tester")
    assert exc.value.status_code == 400


def test_cors_origins_parsing_from_settings():
    custom = system.settings.model_copy(update={"pibg_cors_origins": "https://a.example, https://b.example"})
    assert custom.cors_origins == ["https://a.example", "https://b.example"]
