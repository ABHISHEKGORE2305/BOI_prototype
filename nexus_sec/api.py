# api.py
#
#   uvicorn nexus_sec.api:app

import hashlib
import json
import logging
import os
import time
import uuid
from datetime import timezone

from fastapi import APIRouter
from fastapi import Depends
from fastapi import FastAPI
from fastapi import File
from fastapi import HTTPException
from fastapi import Query
from fastapi import Request
from fastapi import UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST
from prometheus_client import REGISTRY
from prometheus_client import generate_latest
from sqlalchemy import text

from nexus_sec import config
from nexus_sec.database import SessionLocal
from nexus_sec.logging_config import configure_logging
from nexus_sec.logging_config import request_id_var
from nexus_sec.metrics import HTTP_REQUEST_DURATION
from nexus_sec.metrics import UPLOADS
from nexus_sec.metrics import TaskStatusCollector
from nexus_sec.ml import compute_drift
from nexus_sec.ml import model_metadata
from nexus_sec.models import ReportStatus
from nexus_sec.models import Task
from nexus_sec.models import TaskStatus
from nexus_sec.models import utcnow
from nexus_sec.schemas import DriftReport
from nexus_sec.schemas import Health
from nexus_sec.schemas import ModelInfo
from nexus_sec.schemas import TaskDetail
from nexus_sec.schemas import TaskSummary
from nexus_sec.schemas import UploadResponse
from nexus_sec.security import Principal
from nexus_sec.security import authenticate
from nexus_sec.security import enforce_upload_rate_limit
from nexus_sec.worker import celery_app

logger = logging.getLogger(__name__)

# APKs are ZIP archives
ZIP_MAGIC = b"PK\x03\x04"
CHUNK_SIZE = 1024 * 1024

configure_logging()

app = FastAPI(title="Nexus-Sec API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=config.CORS_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-API-Key", "X-Request-ID"],
    expose_headers=["X-Request-ID", "Retry-After"],
)

try:
    REGISTRY.register(TaskStatusCollector(SessionLocal))
except ValueError:
    # Already registered (module re-imported, e.g. by uvicorn --reload)
    pass


@app.middleware("http")
async def request_context(request: Request, call_next):
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    token = request_id_var.set(request_id)
    started = time.perf_counter()
    try:
        response = await call_next(request)
    finally:
        request_id_var.reset(token)

    route = request.scope.get("route")
    HTTP_REQUEST_DURATION.labels(
        request.method,
        route.path if route else "unmatched",
        response.status_code
    ).observe(time.perf_counter() - started)

    response.headers["X-Request-ID"] = request_id
    return response


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def _remove(path):
    try:
        os.remove(path)
    except OSError:
        pass


def save_upload(source, destination, max_bytes):
    """Stream an upload to disk, enforcing size and APK (ZIP) format.

    Returns the file's SHA-256 hex digest.
    """

    digest = hashlib.sha256()
    written = 0
    with open(destination, "wb") as buffer:
        while chunk := source.read(CHUNK_SIZE):
            if written == 0 and not chunk.startswith(ZIP_MAGIC):
                raise HTTPException(
                    status_code=400,
                    detail="File is not a valid APK (ZIP) archive"
                )
            written += len(chunk)
            if written > max_bytes:
                raise HTTPException(
                    status_code=413,
                    detail=f"File exceeds {max_bytes // (1024 * 1024)} MB limit"
                )
            digest.update(chunk)
            buffer.write(chunk)

    if written == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    return digest.hexdigest()


def _load_json(value, default):
    if not value:
        return default
    try:
        return json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return default


def _utc(value):
    # SQLite drops tzinfo; every stored timestamp is UTC
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value


def task_summary(task):
    return TaskSummary(
        task_id=task.id,
        filename=task.filename,
        status=task.status,
        verdict=task.verdict,
        malware_score=task.malware_score,
        created_at=_utc(task.created_at),
    )


def task_detail(task):
    return TaskDetail(
        **task_summary(task).model_dump(),
        sha256=task.sha256,
        model_version=task.model_version,
        shap_data=_load_json(task.shap_data, {}),
        features=_load_json(task.features, {}),
        apk_info=_load_json(task.apk_info, None),
        report_status=task.report_status,
        llm_report=task.llm_report,
        error=task.error,
        cached_from=task.cached_from,
        updated_at=_utc(task.updated_at),
        completed_at=_utc(task.completed_at),
    )


def _find_cached_result(db, sha256):
    metadata = model_metadata()
    if not metadata:
        return None

    return (
        db.query(Task)
        .filter(
            Task.sha256 == sha256,
            Task.status == TaskStatus.COMPLETED,
            Task.model_version == metadata["version"],
        )
        .order_by(Task.completed_at.desc())
        .first()
    )


def _enqueue(name, args, queue):
    celery_app.send_task(
        name,
        args=args,
        kwargs={"request_id": request_id_var.get()},
        queue=queue
    )


def _create_from_cache(db, cached, principal, filename):
    task = Task(
        owner=principal.name,
        filename=filename,
        sha256=cached.sha256,
        status=TaskStatus.COMPLETED,
        verdict=cached.verdict,
        malware_score=cached.malware_score,
        model_version=cached.model_version,
        shap_data=cached.shap_data,
        features=cached.features,
        apk_info=cached.apk_info,
        report_status=cached.report_status,
        llm_report=cached.llm_report,
        cached_from=cached.id,
        completed_at=utcnow(),
    )

    # Re-try the report if the original one never finished
    if cached.report_status != ReportStatus.COMPLETED:
        task.report_status = ReportStatus.PENDING
        task.llm_report = None

    db.add(task)
    db.commit()

    if task.report_status == ReportStatus.PENDING:
        try:
            _enqueue("nexus_sec.tasks.generate_llm_report", [task.id], config.LLM_QUEUE)
        except Exception:
            logger.exception("Failed to enqueue report for cached task %s", task.id)
            task.report_status = ReportStatus.FAILED
            db.commit()

    return task


router = APIRouter(prefix="/api/v1")


# Plain `def` routes so FastAPI runs blocking file and DB I/O in its threadpool
@router.post("/tasks", response_model=UploadResponse, status_code=202)
def upload_apk(
    request: Request,
    file: UploadFile = File(...),
    principal: Principal = Depends(authenticate),
    db=Depends(get_db)
):
    try:
        enforce_upload_rate_limit(request, principal)
    except HTTPException:
        UPLOADS.labels("rate_limited").inc()
        raise

    filename = os.path.basename(file.filename or "")[:255]
    if not filename.lower().endswith(".apk"):
        UPLOADS.labels("rejected").inc()
        raise HTTPException(
            status_code=400,
            detail="Only .apk files are accepted"
        )

    os.makedirs(config.UPLOAD_DIR, exist_ok=True)

    # Never use the client-supplied name on disk
    file_path = os.path.join(config.UPLOAD_DIR, f"{uuid.uuid4().hex}.apk")

    try:
        sha256 = save_upload(file.file, file_path, config.MAX_UPLOAD_BYTES)
    except Exception:
        _remove(file_path)
        UPLOADS.labels("rejected").inc()
        raise

    cached = _find_cached_result(db, sha256)
    if cached is not None:
        _remove(file_path)
        task = _create_from_cache(db, cached, principal, filename)
        UPLOADS.labels("cached").inc()
        logger.info("Reused results of %s for %s", cached.id, task.id)
        return UploadResponse(task_id=task.id, status=task.status, cached=True)

    task = Task(
        owner=principal.name,
        filename=filename,
        sha256=sha256,
        status=TaskStatus.QUEUED
    )
    db.add(task)
    db.commit()

    try:
        _enqueue("nexus_sec.tasks.analyze_apk", [task.id, file_path], config.ANALYSIS_QUEUE)
    except Exception:
        logger.exception("Failed to enqueue task %s", task.id)
        task.status = TaskStatus.FAILED
        task.error = "Could not enqueue analysis job (is Redis running?)"
        db.commit()
        _remove(file_path)
        UPLOADS.labels("queue_error").inc()
        raise HTTPException(
            status_code=503,
            detail="Analysis queue unavailable"
        ) from None

    UPLOADS.labels("accepted").inc()
    return UploadResponse(task_id=task.id, status=task.status, cached=False)


@router.get("/tasks", response_model=list[TaskSummary])
def list_tasks(
    limit: int = Query(20, ge=1, le=100),
    principal: Principal = Depends(authenticate),
    db=Depends(get_db)
):
    tasks = (
        db.query(Task)
        .filter(Task.owner == principal.name)
        .order_by(Task.created_at.desc())
        .limit(limit)
        .all()
    )
    return [task_summary(task) for task in tasks]


@router.get("/tasks/{task_id}", response_model=TaskDetail)
def get_task(
    task_id: str,
    principal: Principal = Depends(authenticate),
    db=Depends(get_db)
):
    task = db.get(Task, task_id)

    # Other users' tasks look exactly like missing ones
    if not task or task.owner != principal.name:
        raise HTTPException(
            status_code=404,
            detail="Task not found"
        )

    return task_detail(task)


def _require_model():
    metadata = model_metadata()
    if not metadata:
        raise HTTPException(
            status_code=503,
            detail="No trained model; run `python -m nexus_sec.train`"
        )
    return metadata


@router.get("/model", response_model=ModelInfo)
def get_model(principal: Principal = Depends(authenticate)):
    metadata = _require_model()
    return ModelInfo(
        version=metadata["version"],
        trained_at=metadata["trained_at"],
        threshold=metadata["threshold"],
        max_fpr=metadata.get("max_fpr"),
        metrics=metadata["test_metrics"],
        global_importance=metadata["global_importance"],
    )


@router.get("/model/drift", response_model=DriftReport)
def get_drift(
    limit: int = Query(500, ge=1, le=5000),
    principal: Principal = Depends(authenticate),
    db=Depends(get_db)
):
    """Feature prevalence in recent scans vs. the training data."""

    metadata = _require_model()

    # One row per distinct APK so re-scans don't skew the statistics
    rows = (
        db.query(Task.features)
        .filter(Task.status == TaskStatus.COMPLETED, Task.cached_from.is_(None))
        .order_by(Task.completed_at.desc())
        .limit(limit)
        .all()
    )

    live = [
        {f for group in _load_json(features, {}).values() for f in group}
        for (features,) in rows
    ]

    return compute_drift(metadata["feature_prevalence"], live)


app.include_router(router)


def _queue_reachable():
    import redis

    try:
        return bool(redis.Redis.from_url(config.REDIS_URL, socket_timeout=1).ping())
    except Exception:
        return False


@app.get("/health", response_model=Health)
def health(response: Response, db=Depends(get_db)):
    try:
        db.execute(text("SELECT 1"))
        database = True
    except Exception:
        logger.exception("Database health check failed")
        database = False

    queue = _queue_reachable()
    ok = database and queue
    if not ok:
        response.status_code = 503

    return Health(
        status="ok" if ok else "unavailable",
        database=database,
        queue=queue,
        model=model_metadata() is not None,
    )


@app.get("/metrics", include_in_schema=False)
def metrics():
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


@app.get("/")
def root():
    return {"message": "API Running", "docs": "/docs"}
