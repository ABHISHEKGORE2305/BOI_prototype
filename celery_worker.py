# celery_worker.py

from celery import Celery

celery_app = Celery(
    "apk_analyzer",
    broker="redis://localhost:6379/0",
    backend="redis://localhost:6379/0"
)

# Use 'solo' pool to avoid fork-based deadlocks with
# LightGBM's internal C++ threading
celery_app.conf.worker_pool = "solo"
