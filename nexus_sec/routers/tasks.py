# routers/tasks.py
#
# Upload an APK, list scans, fetch one scan's results.

import logging
import os
import uuid

from fastapi import APIRouter
from fastapi import Depends
from fastapi import File
from fastapi import HTTPException
from fastapi import Query
from fastapi import Request
from fastapi import UploadFile

from nexus_sec import config
from nexus_sec.database import get_db
from nexus_sec.metrics import UPLOADS
from nexus_sec.models import Task
from nexus_sec.schemas import TaskDetail
from nexus_sec.schemas import TaskSummary
from nexus_sec.schemas import UploadResponse
from nexus_sec.security import Principal
from nexus_sec.security import authenticate
from nexus_sec.security import enforce_upload_rate_limit
from nexus_sec.services import tasks as task_service
from nexus_sec.services.uploads import remove_file
from nexus_sec.services.uploads import save_upload

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/tasks", tags=["tasks"])


# Plain `def` routes so FastAPI runs blocking file and DB I/O in its threadpool
@router.post("", response_model=UploadResponse, status_code=202)
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
        remove_file(file_path)
        UPLOADS.labels("rejected").inc()
        raise

    cached = task_service.find_cached_result(db, sha256)
    if cached is not None:
        remove_file(file_path)
        task = task_service.create_from_cache(db, cached, principal.name, filename)
        UPLOADS.labels("cached").inc()
        logger.info("Reused results of %s for %s", cached.id, task.id)
        return UploadResponse(task_id=task.id, status=task.status, cached=True)

    try:
        task = task_service.create_and_enqueue(db, principal.name, filename, sha256, file_path)
    except Exception:
        remove_file(file_path)
        UPLOADS.labels("queue_error").inc()
        raise HTTPException(
            status_code=503,
            detail="Analysis queue unavailable"
        ) from None

    UPLOADS.labels("accepted").inc()
    return UploadResponse(task_id=task.id, status=task.status, cached=False)


@router.get("", response_model=list[TaskSummary])
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
    return [task_service.task_summary(task) for task in tasks]


@router.get("/{task_id}", response_model=TaskDetail)
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

    return task_service.task_detail(task)
