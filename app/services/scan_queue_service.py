import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Callable, Optional
from uuid import uuid4

logger = logging.getLogger("pibroadguard.scan_queue")


class ScanJobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ScanJob:
    job_id: str
    assessment_id: int
    device_id: int
    ip_address: str
    scan_profile: str
    triggered_by: str  # "manual" | "schedule"
    schedule_id: Optional[int] = None
    interface: Optional[str] = None  # network interface for nmap -e; None/"auto" = let nmap decide
    queued_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    status: ScanJobStatus = ScanJobStatus.QUEUED
    position: int = 0


# Module-level singleton
_instance: Optional["ScanQueueService"] = None


def get_queue() -> Optional["ScanQueueService"]:
    return _instance


def init_queue(max_parallel: int = 1) -> "ScanQueueService":
    global _instance
    _instance = ScanQueueService(max_parallel)
    return _instance


class ScanQueueService:
    def __init__(self, max_parallel: int = 1):
        self._queue: asyncio.Queue = asyncio.Queue()
        self._running: dict[str, ScanJob] = {}
        self._max_parallel = max_parallel
        self._semaphore = asyncio.Semaphore(max_parallel)
        self._history: list[ScanJob] = []
        self._job_processor: Optional[Callable] = None

    def set_job_processor(self, fn: Callable) -> None:
        self._job_processor = fn

    async def enqueue(self, job: ScanJob) -> ScanJob:
        """Add job to queue. Prevents duplicate scans on the same device."""
        # Check if device already queued
        for queued in list(self._queue._queue):  # type: ignore[attr-defined]
            if queued.device_id == job.device_id:
                job.status = ScanJobStatus.SKIPPED
                logger.warning(f"Device {job.device_id} already queued, skipping job {job.job_id}")
                return job

        # Check if device already running
        if any(j.device_id == job.device_id for j in self._running.values()):
            job.status = ScanJobStatus.SKIPPED
            logger.warning(f"Device {job.device_id} scan already running, skipping job {job.job_id}")
            return job

        job.position = self._queue.qsize() + len(self._running) + 1
        await self._queue.put(job)
        logger.info(f"Scan job {job.job_id} queued at position {job.position}")
        return job

    async def worker(self) -> None:
        """Runs as asyncio task (started in main.py startup). Processes jobs sequentially."""
        logger.info(f"Scan queue worker started (max_parallel={self._max_parallel})")
        while True:
            job = await self._queue.get()
            async with self._semaphore:
                self._running[job.job_id] = job
                job.status = ScanJobStatus.RUNNING
                job.started_at = datetime.utcnow()
                logger.info(f"Scan job {job.job_id} starting (assessment={job.assessment_id})")
                try:
                    if self._job_processor:
                        await self._job_processor(job.assessment_id, job.ip_address, job.scan_profile, job.interface)
                    job.status = ScanJobStatus.DONE
                    logger.info(f"Scan job {job.job_id} completed successfully")
                except Exception as e:
                    job.status = ScanJobStatus.FAILED
                    logger.error(f"Scan job {job.job_id} failed: {e}")
                finally:
                    self._running.pop(job.job_id, None)
                    self._history.insert(0, job)
                    self._history = self._history[:50]
                    self._queue.task_done()

    def get_status(self) -> dict:
        """Returns queue state for API endpoint and UI polling."""
        queued_jobs = list(self._queue._queue)  # type: ignore[attr-defined]
        return {
            "queued": [
                {
                    "job_id": j.job_id,
                    "assessment_id": j.assessment_id,
                    "device_id": j.device_id,
                    "ip_address": j.ip_address,
                    "scan_profile": j.scan_profile,
                    "triggered_by": j.triggered_by,
                    "queued_at": j.queued_at.isoformat(),
                    "position": i + 1,
                    "status": j.status,
                }
                for i, j in enumerate(queued_jobs)
            ],
            "running": [
                {
                    "job_id": j.job_id,
                    "assessment_id": j.assessment_id,
                    "device_id": j.device_id,
                    "ip_address": j.ip_address,
                    "scan_profile": j.scan_profile,
                    "triggered_by": j.triggered_by,
                    "started_at": j.started_at.isoformat() if j.started_at else None,
                    "status": j.status,
                }
                for j in self._running.values()
            ],
            "history": [
                {
                    "job_id": j.job_id,
                    "assessment_id": j.assessment_id,
                    "device_id": j.device_id,
                    "scan_profile": j.scan_profile,
                    "triggered_by": j.triggered_by,
                    "started_at": j.started_at.isoformat() if j.started_at else None,
                    "queued_at": j.queued_at.isoformat(),
                    "status": j.status,
                }
                for j in self._history[:10]
            ],
            "max_parallel": self._max_parallel,
        }

    async def cancel(self, job_id: str) -> bool:
        """Remove job from queue (only if not yet started)."""
        items = []
        cancelled = False
        while not self._queue.empty():
            try:
                item = self._queue.get_nowait()
                if item.job_id == job_id:
                    cancelled = True
                    self._queue.task_done()
                else:
                    items.append(item)
            except asyncio.QueueEmpty:
                break
        for item in items:
            await self._queue.put(item)
        if cancelled:
            logger.info(f"Scan job {job_id} cancelled from queue")
        return cancelled
