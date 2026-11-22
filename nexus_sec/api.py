# api.py
#
# FastAPI application: middleware, routers, health and metrics.
#
#   uvicorn nexus_sec.api:app

import logging
import time
import uuid

from fastapi import APIRouter
from fastapi import Depends
from fastapi import FastAPI
from fastapi import Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from prometheus_client import CONTENT_TYPE_LATEST
from prometheus_client import REGISTRY
from prometheus_client import generate_latest
from sqlalchemy import text

from nexus_sec import config
from nexus_sec import ml
from nexus_sec.database import SessionLocal
from nexus_sec.database import get_db
from nexus_sec.logging_config import configure_logging
from nexus_sec.logging_config import request_id_var
from nexus_sec.metrics import HTTP_REQUEST_DURATION
from nexus_sec.metrics import TaskStatusCollector
from nexus_sec.routers import model as model_routes
from nexus_sec.routers import tasks as task_routes
from nexus_sec.schemas import Health

logger = logging.getLogger(__name__)

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


v1 = APIRouter(prefix="/api/v1")
v1.include_router(task_routes.router)
v1.include_router(model_routes.router)
app.include_router(v1)


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
        model=ml.model_metadata() is not None,
    )


@app.get("/metrics", include_in_schema=False)
def metrics():
    return Response(generate_latest(REGISTRY), media_type=CONTENT_TYPE_LATEST)


@app.get("/")
def root():
    return {"message": "API Running", "docs": "/docs"}
