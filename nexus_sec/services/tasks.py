# services/tasks.py
#
# Task lifecycle on the API side: result caching, enqueueing jobs for the
# workers and converting database rows to response schemas.

import json
import logging
from datetime import timezone

from nexus_sec import config
from nexus_sec import ml
from nexus_sec.logging_config import request_id_var
from nexus_sec.models import ReportStatus
from nexus_sec.models import Task
from nexus_sec.models import TaskStatus
from nexus_sec.models import utcnow
from nexus_sec.schemas import TaskDetail
from nexus_sec.schemas import TaskSummary
from nexus_sec.worker import celery_app

logger = logging.getLogger(__name__)

ANALYZE_TASK = "nexus_sec.tasks.analyze_apk"
REPORT_TASK = "nexus_sec.tasks.generate_llm_report"


def load_json(value, default):
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
        shap_data=load_json(task.shap_data, {}),
        features=load_json(task.features, {}),
        apk_info=load_json(task.apk_info, None),
        report_status=task.report_status,
        llm_report=task.llm_report,
        error=task.error,
        cached_from=task.cached_from,
        updated_at=_utc(task.updated_at),
        completed_at=_utc(task.completed_at),
    )


def enqueue(name, args, queue):
    # By name, so the API process never imports the ML stack
    celery_app.send_task(
        name,
        args=args,
        kwargs={"request_id": request_id_var.get()},
        queue=queue
    )


def find_cached_result(db, sha256):
    """Latest completed scan of the same file by the current model, if any."""

    metadata = ml.model_metadata()
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


def create_from_cache(db, cached, owner, filename):
    task = Task(
        owner=owner,
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
            enqueue(REPORT_TASK, [task.id], config.LLM_QUEUE)
        except Exception:
            logger.exception("Failed to enqueue report for cached task %s", task.id)
            task.report_status = ReportStatus.FAILED
            db.commit()

    return task


def create_and_enqueue(db, owner, filename, sha256, file_path):
    """Insert a queued task and hand it to the analysis worker.

    Raises if the queue is unreachable, after marking the task failed.
    """

    task = Task(owner=owner, filename=filename, sha256=sha256, status=TaskStatus.QUEUED)
    db.add(task)
    db.commit()

    try:
        enqueue(ANALYZE_TASK, [task.id, file_path], config.ANALYSIS_QUEUE)
    except Exception:
        logger.exception("Failed to enqueue task %s", task.id)
        task.status = TaskStatus.FAILED
        task.error = "Could not enqueue analysis job (is Redis running?)"
        db.commit()
        raise

    return task
