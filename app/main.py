import asyncio
import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from alembic.config import Config as AlembicConfig
from alembic import command as alembic_command

from app.core.config import settings
from app.core.logging_config import setup_logging
from app.core.security import limiter
from app.core.database import SessionLocal

from app.api.v1 import devices, assessments, scans, reports, system, import_export, usb, cve

VERSION = "1.0.0"
API_VERSION = "v1"

# Setup logging first
os.makedirs(os.path.dirname(settings.pibg_log_path), exist_ok=True)
setup_logging(settings.pibg_log_level, settings.pibg_log_path)
logger = logging.getLogger("pibroadguard")


def run_migrations():
    try:
        cfg = AlembicConfig("alembic.ini")
        alembic_command.upgrade(cfg, "head")
        logger.info("Database migrations applied")
    except Exception as e:
        logger.warning(f"Migration failed (may be ok on first run): {e}")
        # Fallback: create tables directly
        from app.core.database import Base, engine
        import app.models  # noqa
        Base.metadata.create_all(bind=engine)
        logger.info("Tables created via SQLAlchemy directly")


def init_default_settings(db):
    from app.models.system_settings import SystemSettings
    from datetime import datetime, timezone
    defaults = {
        "connectivity_mode": "auto",
        "encryption_enabled": "true",
    }
    for key, value in defaults.items():
        existing = db.query(SystemSettings).filter(SystemSettings.key == key).first()
        if not existing:
            db.add(SystemSettings(key=key, value=value, updated_by="system",
                                  updated_at=datetime.now(timezone.utc)))
    db.commit()


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    run_migrations()
    db = SessionLocal()
    try:
        init_default_settings(db)
    finally:
        db.close()

    from app.services import nmap_service, connectivity_service
    asyncio.create_task(nmap_service.get_nmap_capabilities())
    asyncio.create_task(connectivity_service.check_internet())

    # KEV sync in background
    async def kev_task():
        db2 = SessionLocal()
        try:
            from app.services import remediation_service
            await remediation_service.sync_kev_if_stale(db2)
        finally:
            db2.close()
    asyncio.create_task(kev_task())

    logger.info(f"PiBroadGuard v{VERSION} started")
    yield
    # Shutdown
    logger.info("PiBroadGuard shutting down")


app = FastAPI(
    title="PiBroadGuard",
    description="Broadcast Device Security Assessment Tool",
    version=VERSION,
    lifespan=lifespan,
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# API routers
PREFIX = f"/api/{API_VERSION}"
app.include_router(devices.router, prefix=PREFIX)
app.include_router(assessments.router, prefix=PREFIX)
app.include_router(scans.router, prefix=PREFIX)
app.include_router(reports.router, prefix=PREFIX)
app.include_router(system.router, prefix=PREFIX)
app.include_router(import_export.router, prefix=PREFIX)
app.include_router(usb.router, prefix=PREFIX)
app.include_router(cve.router, prefix=PREFIX)


@app.middleware("http")
async def add_version_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-PiBroadGuard-Version"] = VERSION
    response.headers["X-PiBroadGuard-API"] = API_VERSION
    return response


# Health + Version (no auth)
@app.get("/health")
def health():
    return {"status": "ok", "version": VERSION}


@app.get("/version")
def version():
    return {"version": VERSION, "api": API_VERSION}


# Frontend: serve static files with Basic Auth protection
@app.get("/")
def root(request: Request):
    return RedirectResponse("/app/index.html")


# Serve frontend files (with auth check via middleware)
@app.middleware("http")
async def protect_frontend(request: Request, call_next):
    path = request.url.path
    # Public paths (no auth)
    if path in ("/health", "/version") or path.startswith("/api/"):
        return await call_next(request)
    # All other paths require auth
    if path.startswith("/app/") or path == "/":
        auth = request.headers.get("authorization")
        if not auth or not _check_basic_auth(auth):
            return Response(
                status_code=401,
                headers={"WWW-Authenticate": 'Basic realm="PiBroadGuard"'},
                content="Unauthorized",
            )
    return await call_next(request)


def _check_basic_auth(auth_header: str) -> bool:
    import base64
    import secrets
    try:
        scheme, credentials = auth_header.split(" ", 1)
        if scheme.lower() != "basic":
            return False
        decoded = base64.b64decode(credentials).decode("utf-8")
        username, password = decoded.split(":", 1)
        ok_u = secrets.compare_digest(username, settings.username)
        ok_p = secrets.compare_digest(password, settings.password)
        return ok_u and ok_p
    except Exception:
        return False


# Mount frontend after middleware
frontend_path = os.path.join(os.path.dirname(__file__), "..", "frontend")
if os.path.isdir(frontend_path):
    app.mount("/app", StaticFiles(directory=frontend_path, html=True), name="frontend")
