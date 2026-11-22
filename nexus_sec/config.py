# config.py
#
# Central settings, read from the environment (or a .env file).
# The API and the Celery workers import this, so paths are absolute
# and do not depend on the working directory.

import os

from dotenv import load_dotenv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

load_dotenv(os.path.join(BASE_DIR, ".env"))


def _env_int(name, default):
    return int(os.getenv(name, default))


def _env_float(name, default):
    return float(os.getenv(name, default))


def _env_list(name, default=""):
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


DATABASE_URL = os.getenv(
    "DATABASE_URL",
    f"sqlite:///{os.path.join(BASE_DIR, 'malware.db')}"
)

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")

UPLOAD_DIR = os.getenv("UPLOAD_DIR", os.path.join(BASE_DIR, "uploads"))

MAX_UPLOAD_BYTES = _env_int("MAX_UPLOAD_MB", 100) * 1024 * 1024

CORS_ORIGINS = _env_list(
    "CORS_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173"
)

# --- Security ---------------------------------------------------------------

# Comma-separated API keys, optionally named: "alice:key1,bob:key2".
# Empty disables authentication (local development only).
API_KEYS = _env_list("API_KEYS")

# Uploads allowed per client (API key, or IP when auth is off) per minute
UPLOAD_RATE_LIMIT_PER_MINUTE = _env_int("UPLOAD_RATE_LIMIT_PER_MINUTE", 10)

# --- Worker -----------------------------------------------------------------

# Seconds before a running analysis is aborted and marked failed
ANALYSIS_TIME_LIMIT = _env_int("ANALYSIS_TIME_LIMIT", 600)

# Delete scan results older than this many days (0 keeps them forever)
RESULT_RETENTION_DAYS = _env_int("RESULT_RETENTION_DAYS", 30)

# Port for the worker's Prometheus metrics endpoint (0 disables it)
WORKER_METRICS_PORT = _env_int("WORKER_METRICS_PORT", 0)

ANALYSIS_QUEUE = "analysis"
LLM_QUEUE = "llm"

# --- Model ------------------------------------------------------------------

MODEL_DIR = os.getenv("MODEL_DIR", os.path.join(BASE_DIR, "models"))
MODEL_PATH = os.path.join(MODEL_DIR, "malware_model.pkl")
FEATURE_NAMES_PATH = os.path.join(MODEL_DIR, "feature_names.json")
METRICS_PATH = os.path.join(MODEL_DIR, "metrics.json")
FEATURE_CATEGORIES_PATH = os.path.join(
    BASE_DIR, "datasets", "dataset-features-categories.csv"
)

# --- LLM --------------------------------------------------------------------

GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
GEMINI_MODEL = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
LLM_MAX_RETRIES = _env_int("LLM_MAX_RETRIES", 3)

# --- Logging ----------------------------------------------------------------

LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
# "text" for development, "json" for log aggregation
LOG_FORMAT = os.getenv("LOG_FORMAT", "text")

# Lowest malware probability treated as malicious when the model bundle
# doesn't carry a tuned threshold
DEFAULT_THRESHOLD = _env_float("DEFAULT_THRESHOLD", 0.5)
