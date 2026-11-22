# Operations, Configuration & Troubleshooting

## Observability

- **Logs** — `LOG_FORMAT=json` (default in Docker) emits one JSON object per line with `request_id` and `task_id`. Pass `X-Request-ID` to correlate a request through the API and both workers.
- **Metrics** — API `GET /metrics`; analysis worker on `WORKER_METRICS_PORT` (9100 in Docker). Key series: `nexus_uploads_total{outcome}`, `nexus_analyses_total{outcome}`, `nexus_analysis_duration_seconds`, `nexus_llm_reports_total{outcome}`, `nexus_tasks{status}`, `nexus_http_request_duration_seconds`.
- **Health** — `GET /health` checks database and Redis; used by the Compose healthcheck.
- **Drift** — the dashboard's *Model & drift* tab (or `GET /api/v1/model/drift`) compares indicator prevalence in recent distinct scans with the training data.

## Configuration

Backend settings are read from the environment or `.env` (see `.env.example`).

| Variable | Description | Default |
| :--- | :--- | :--- |
| `GEMINI_API_KEY` | Enables LLM reports (only the LLM worker needs it) | — |
| `GEMINI_MODEL` | Gemini model name | `gemini-2.5-flash` |
| `LLM_MAX_RETRIES` | Retries (exponential backoff) before a report is marked failed | `3` |
| `DATABASE_URL` | SQLAlchemy URL | `sqlite:///<repo>/malware.db` |
| `REDIS_URL` | Celery broker | `redis://localhost:6379/0` |
| `API_KEYS` | `name:key` pairs, comma-separated; empty disables auth | — |
| `UPLOAD_RATE_LIMIT_PER_MINUTE` | Uploads per key / IP per minute (0 = unlimited) | `10` |
| `RATE_LIMIT_BACKEND` | `redis` (shared across replicas) or `memory` (per process) | `redis` |
| `UPLOAD_DIR` | Shared by API and analysis worker | `<repo>/uploads` |
| `MAX_UPLOAD_MB` | Maximum APK size | `100` |
| `CORS_ORIGINS` | Allowed browser origins | `http://localhost:5173,http://127.0.0.1:5173` |
| `ANALYSIS_TIME_LIMIT` | Seconds before an analysis is aborted | `600` |
| `RESULT_RETENTION_DAYS` | Delete results older than this (0 = keep) | `30` |
| `WORKER_METRICS_PORT` | Worker Prometheus port (0 = off) | `0` |
| `LOG_LEVEL` / `LOG_FORMAT` | Logging level / `text` or `json` | `INFO` / `text` |
| `MODEL_DIR` | Model bundle location | `<repo>/models` |

Frontend variables are listed in `frontend/.env.example`.

## Troubleshooting

<details>
<summary><strong>Worker task fails with "Model not found" or "predates the current bundle format"</strong></summary>

Run `python -m nexus_sec.train` to (re)create `models/malware_model.pkl`.
</details>

<details>
<summary><strong>"no such table" / "no such column" database errors</strong></summary>

Run `alembic upgrade head`. A `malware.db` created by versions before migrations existed can't be upgraded in place; delete it and run the command again.
</details>

<details>
<summary><strong>Scans stay "queued"</strong></summary>

No worker is consuming the `analysis` queue. Start one with `celery -A nexus_sec.worker worker -Q analysis,llm`. `GET /health` reports whether Redis is reachable.
</details>

<details>
<summary><strong>Report stays "Generating…" or shows "not configured"</strong></summary>

A worker must consume the `llm` queue, and `GEMINI_API_KEY` must be set **for that worker**. Failures are retried `LLM_MAX_RETRIES` times; the worker log shows the underlying error.
</details>

<details>
<summary><strong>Androguard fails on some APKs</strong></summary>

Heavily obfuscated or malformed APKs can break parsing. The reason is stored on the task and shown in the dashboard. Use `androguard>=4.1` on Python 3.10–3.12.
</details>

<details>
<summary><strong>Celery worker hangs during LightGBM inference</strong></summary>

The worker must use the `solo` pool (the default set in `nexus_sec/worker.py`); don't override it with `--pool=prefork`.
</details>
