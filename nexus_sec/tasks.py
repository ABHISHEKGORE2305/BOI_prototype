# tasks.py
#
# Celery pipeline:
#   analyze_apk          Androguard -> Drebin features -> LightGBM -> SHAP
#   generate_llm_report  Gemini SOC report (separate queue, retried)
#   purge_expired        retention clean-up (Celery beat)

import json
import logging
import os
import signal
import threading
import time
from contextlib import contextmanager
from datetime import timedelta
from functools import lru_cache

from nexus_sec import config
from nexus_sec.database import SessionLocal
from nexus_sec.extractor import extract_artifacts
from nexus_sec.features import build_feature_vector
from nexus_sec.features import match_features
from nexus_sec.llm import LLMUnavailableError
from nexus_sec.llm import build_prompt
from nexus_sec.llm import generate_report
from nexus_sec.logging_config import request_id_var
from nexus_sec.logging_config import task_id_var
from nexus_sec.metrics import ANALYSES
from nexus_sec.metrics import ANALYSIS_DURATION
from nexus_sec.metrics import LLM_REPORTS
from nexus_sec.ml import load_model
from nexus_sec.models import ReportStatus
from nexus_sec.models import Task
from nexus_sec.models import TaskStatus
from nexus_sec.models import utcnow
from nexus_sec.worker import celery_app

logger = logging.getLogger(__name__)

# Uploads older than this with no running task are leftovers from crashes
ORPHAN_UPLOAD_SECONDS = 24 * 3600


class AnalysisTimeout(Exception):
    pass


@contextmanager
def time_limit(seconds):
    """Abort the block after `seconds` (the solo pool runs tasks in the main thread)."""

    if (
        seconds <= 0
        or not hasattr(signal, "SIGALRM")
        or threading.current_thread() is not threading.main_thread()
    ):
        yield
        return

    def on_timeout(signum, frame):
        raise AnalysisTimeout(f"Analysis exceeded {seconds}s time limit")

    previous = signal.signal(signal.SIGALRM, on_timeout)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


@lru_cache(maxsize=1)
def feature_vocabulary():
    with open(config.FEATURE_NAMES_PATH) as f:
        return tuple(json.load(f))


def _remove(path):
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        logger.warning("Could not delete %s", path)


@celery_app.task(name="nexus_sec.tasks.analyze_apk")
def analyze_apk(task_id, file_path, request_id=None):

    request_id_var.set(request_id)
    task_id_var.set(task_id)
    started = time.monotonic()

    db = SessionLocal()
    task = db.get(Task, task_id)

    try:
        if task is None:
            logger.error("Task not found; dropping job")
            return

        task.status = TaskStatus.PROCESSING
        db.commit()

        with time_limit(config.ANALYSIS_TIME_LIMIT):
            model = load_model()

            artifacts, info = extract_artifacts(file_path)
            matched = match_features(artifacts, model.feature_names, model.categories)
            feature_vector = build_feature_vector(matched, model.feature_names)

            logger.info(
                "Matched %d / %d features",
                int(feature_vector.values.sum()),
                len(model.feature_names)
            )

            probability = model.malware_probability(feature_vector)
            top_features = model.top_shap_features(feature_vector)

        task.status = TaskStatus.COMPLETED
        task.verdict = model.verdict(probability)
        task.malware_score = round(probability * 100, 2)
        task.model_version = model.version
        task.shap_data = json.dumps(top_features)
        task.features = json.dumps(matched)
        task.apk_info = json.dumps(info)
        # The LLM worker decides whether a report can be generated; the
        # analysis worker deliberately has no API key or internet access
        task.report_status = ReportStatus.PENDING
        task.error = None
        task.completed_at = utcnow()
        db.commit()

        ANALYSES.labels("completed").inc()
        ANALYSIS_DURATION.observe(time.monotonic() - started)
        logger.info("Completed: %s, score %.2f", task.verdict, task.malware_score)

        _enqueue_report(db, task, request_id)

    except Exception as e:
        logger.exception("Analysis failed")
        ANALYSES.labels("failed").inc()
        db.rollback()
        if task is not None:
            task.status = TaskStatus.FAILED
            task.error = f"{type(e).__name__}: {e}"[:2000]
            task.completed_at = utcnow()
            db.commit()
        raise

    finally:
        _remove(file_path)
        db.close()


def _enqueue_report(db, task, request_id):
    try:
        generate_llm_report.apply_async(
            args=[task.id],
            kwargs={"request_id": request_id},
            queue=config.LLM_QUEUE
        )
    except Exception:
        logger.exception("Could not enqueue LLM report")
        task.report_status = ReportStatus.FAILED
        db.commit()


@celery_app.task(
    name="nexus_sec.tasks.generate_llm_report",
    bind=True,
    max_retries=config.LLM_MAX_RETRIES
)
def generate_llm_report(self, task_id, request_id=None):

    request_id_var.set(request_id)
    task_id_var.set(task_id)

    db = SessionLocal()
    try:
        task = db.get(Task, task_id)
        if task is None or task.status != TaskStatus.COMPLETED:
            return

        prompt = build_prompt(
            task.malware_score,
            task.verdict,
            json.loads(task.features or "{}"),
            json.loads(task.shap_data or "{}"),
            feature_vocabulary()
        )

        try:
            report = generate_report(prompt)
        except LLMUnavailableError:
            task.report_status = ReportStatus.SKIPPED
            db.commit()
            LLM_REPORTS.labels("skipped").inc()
            return
        except Exception as exc:
            if self.request.retries < self.max_retries:
                LLM_REPORTS.labels("retried").inc()
                logger.warning("LLM report failed (%s); retrying", exc)
                raise self.retry(exc=exc, countdown=5 * 2 ** self.request.retries) from exc

            logger.exception("LLM report failed after %d retries", self.max_retries)
            task.report_status = ReportStatus.FAILED
            db.commit()
            LLM_REPORTS.labels("failed").inc()
            return

        task.llm_report = report
        task.report_status = ReportStatus.COMPLETED
        db.commit()
        LLM_REPORTS.labels("completed").inc()

    finally:
        db.close()


@celery_app.task(name="nexus_sec.tasks.purge_expired")
def purge_expired():
    deleted_tasks = 0
    if config.RESULT_RETENTION_DAYS > 0:
        cutoff = utcnow() - timedelta(days=config.RESULT_RETENTION_DAYS)
        db = SessionLocal()
        try:
            deleted_tasks = (
                db.query(Task)
                .filter(Task.created_at < cutoff)
                .delete(synchronize_session=False)
            )
            db.commit()
        finally:
            db.close()

    deleted_uploads = 0
    if os.path.isdir(config.UPLOAD_DIR):
        cutoff_mtime = time.time() - ORPHAN_UPLOAD_SECONDS
        for name in os.listdir(config.UPLOAD_DIR):
            path = os.path.join(config.UPLOAD_DIR, name)
            if os.path.isfile(path) and os.path.getmtime(path) < cutoff_mtime:
                _remove(path)
                deleted_uploads += 1

    logger.info(
        "Retention: deleted %d tasks, %d orphaned uploads",
        deleted_tasks,
        deleted_uploads
    )
    return {"tasks": deleted_tasks, "uploads": deleted_uploads}
