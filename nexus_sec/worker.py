# worker.py
#
# Celery application. Two queues keep untrusted-APK parsing apart from the
# LLM call, so they can run in different containers:
#
#   analysis  Androguard + model (needs no internet access)
#   llm       Gemini report generation (never touches the APK)
#
# Development: one worker can consume both queues, with -B for retention:
#   celery -A nexus_sec.worker worker -Q analysis,llm -B --loglevel=info

from celery import Celery
from celery.signals import setup_logging
from celery.signals import worker_init

from nexus_sec import config

celery_app = Celery(
    "nexus_sec",
    broker=config.REDIS_URL,
    backend=config.REDIS_URL,
    include=["nexus_sec.tasks"]
)

celery_app.conf.update(
    # Use 'solo' pool to avoid fork-based deadlocks with
    # LightGBM's internal C++ threading
    worker_pool="solo",
    worker_prefetch_multiplier=1,
    task_default_queue=config.ANALYSIS_QUEUE,
    task_routes={
        "nexus_sec.tasks.analyze_apk": {"queue": config.ANALYSIS_QUEUE},
        "nexus_sec.tasks.purge_expired": {"queue": config.ANALYSIS_QUEUE},
        "nexus_sec.tasks.generate_llm_report": {"queue": config.LLM_QUEUE},
    },
    beat_schedule={
        "purge-expired": {
            "task": "nexus_sec.tasks.purge_expired",
            "schedule": 3600.0,
        },
    },
    # Results live in the database, not the Celery backend
    task_ignore_result=True,
)

# Note: Celery's task_time_limit is not enforced by the solo pool;
# tasks.py applies config.ANALYSIS_TIME_LIMIT itself.


@setup_logging.connect
def _setup_logging(**kwargs):
    from nexus_sec.logging_config import configure_logging

    configure_logging()


@worker_init.connect
def _start_metrics_server(**kwargs):
    if config.WORKER_METRICS_PORT:
        from prometheus_client import start_http_server

        start_http_server(config.WORKER_METRICS_PORT)
