import logging
import secrets
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from slowapi import Limiter
from slowapi.util import get_remote_address
from app.core.config import settings

logger = logging.getLogger("pibroadguard.auth")

security = HTTPBasic()
limiter = Limiter(key_func=get_remote_address)

_failed_attempts: dict[str, int] = {}
_logged_logins: set[str] = set()
MAX_FAILURES = 10


def verify_credentials(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(security),
) -> str:
    correct_user = secrets.compare_digest(credentials.username, settings.username)
    correct_pass = secrets.compare_digest(credentials.password, settings.password)
    if not (correct_user and correct_pass):
        ip = request.client.host if request.client else "unknown"
        _failed_attempts[ip] = _failed_attempts.get(ip, 0) + 1
        logger.warning(
            f"Failed auth attempt from {ip} (attempt #{_failed_attempts[ip]})"
        )
        if _failed_attempts[ip] >= MAX_FAILURES:
            raise HTTPException(
                status_code=429,
                detail="Too many failed attempts",
                headers={"Retry-After": "300"},
            )
        raise HTTPException(
            status_code=401,
            headers={"WWW-Authenticate": "Basic"},
            detail="Ungültige Zugangsdaten",
        )
    ip = request.client.host if request.client else "unknown"
    _failed_attempts.pop(ip, None)
    # Log first successful login from each IP (avoids spamming per-request)
    # We track by presence in _logged_logins (module-level set)
    if ip not in _logged_logins:
        _logged_logins.add(ip)
        logger.info(f"Successful auth from {ip} (user: {credentials.username})")
    return credentials.username
