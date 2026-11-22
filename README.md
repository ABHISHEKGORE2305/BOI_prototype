# 🛡️ Nexus-Sec: Android Malware Analysis & Threat Intelligence Platform

[![CI](https://github.com/ABHISHEKGORE2305/BOI_prototype/actions/workflows/ci.yml/badge.svg)](https://github.com/ABHISHEKGORE2305/BOI_prototype/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688.svg?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com/)
[![React](https://img.shields.io/badge/React-18.3-61DAFB.svg?logo=react&logoColor=black)](https://react.dev/)
[![Celery](https://img.shields.io/badge/Celery-5.x-37814A.svg?logo=celery&logoColor=white)](https://docs.celeryq.dev/)
[![LightGBM](https://img.shields.io/badge/ML-LightGBM-brightgreen.svg)](https://lightgbm.readthedocs.io/)
[![SHAP](https://img.shields.io/badge/Explainability-SHAP-ff69b4.svg)](https://shap.readthedocs.io/)
[![Gemini](https://img.shields.io/badge/GenAI-Gemini-4285F4.svg?logo=google&logoColor=white)](https://ai.google.dev/)

**Nexus-Sec** is a prototype for automated Android APK static analysis, machine-learning malware classification, model explainability, and generative-AI threat intelligence.

It combines static reverse engineering (**Androguard**), a calibrated gradient-boosted classifier (**LightGBM** trained on the Drebin-215 dataset), game-theoretic explainability (**SHAP**) and an LLM (**Google Gemini**) so SOC analysts can see whether an app is likely malicious, *why* it was flagged, and what to do about it.

---

## 📑 Table of Contents

- [System Architecture](#-system-architecture)
- [Key Features](#-key-features)
- [Tech Stack](#-tech-stack)
- [Directory Structure](#-directory-structure)
- [Machine Learning & Dataset](#-machine-learning--dataset)
- [Quick Start (Docker)](#-quick-start-docker)
- [Local Development](#-local-development)
- [REST API Reference](#-rest-api-reference)
- [Frontend Dashboard](#️-frontend-dashboard)
- [Security Model](#-security-model)
- [Operations](#-operations)
- [Configuration & Environment Variables](#️-configuration--environment-variables)
- [Testing & CI](#-testing--ci)
- [Troubleshooting & FAQ](#-troubleshooting--faq)
- [Roadmap](#-roadmap)

---

## 🏛 System Architecture

```mermaid
flowchart TD
    User(["SOC Analyst"]) -->|Upload APK| UI["React Dashboard (nginx)"]
    UI -->|"POST /api/v1/tasks"| API["FastAPI"]
    API -->|"SHA-256 cache hit"| DB
    API -->|"Save APK, insert task"| DB[("PostgreSQL / SQLite")]
    API -->|"Enqueue (analysis queue)"| Redis[("Redis")]

    subgraph Isolated ["analysis-worker (no internet, read-only FS)"]
        Redis --> Extract["Androguard static extraction"]
        Extract --> Features["Drebin-215 feature matcher"]
        Features --> Model["LightGBM + isotonic calibration"]
        Model --> SHAP["SHAP TreeExplainer"]
    end

    SHAP -->|"Verdict, score, indicators"| DB
    SHAP -->|"Enqueue (llm queue)"| Redis

    subgraph LLM ["llm-worker (internet egress, no APK access)"]
        Redis --> Gemini["Gemini report (retried with backoff)"]
    end

    Gemini -->|"Report"| DB
    Beat["Celery beat"] -->|"Hourly retention purge"| DB
    UI -->|"Poll GET /api/v1/tasks/:id"| API
```

Classification and report generation are separate tasks on separate queues. A Gemini outage never delays or loses a verdict, and the process that parses untrusted APKs has no network route to the internet.

---

## ✨ Key Features

1. **Static bytecode & manifest inspection** — Androguard extracts permissions, intent filters (all component types), referenced classes/methods (including the app's own overrides and implemented interfaces) and DEX string constants. Analyst-facing metadata (package, SDK levels, signing certificates, native libraries, debuggable flag) is recorded separately.
2. **Faithful Drebin feature mapping** — the 215-feature schema mixes several naming styles (`transact`, `DexClassLoader`, `android.os.Binder`, `Ljava.lang.Class.forName`, `TelephonyManager.getDeviceId`, `HttpGet.init`, `chmod`, intent actions). Each feature is matched by its category; see [`nexus_sec/features.py`](nexus_sec/features.py).
3. **Calibrated ML verdicts** — LightGBM with isotonic probability calibration and a decision threshold tuned to a false-positive budget (default ≤ 1 %). Every result records the model version that produced it.
4. **Explainable AI** — per-scan SHAP attributions plus global importance across the test set.
5. **GenAI threat reports** — Gemini drafts an executive summary, classification, behaviour analysis and recommended actions from the matched indicators only.
6. **Analyst dashboard** — risk gauge, SHAP chart, Markdown report, indicator tables with reference descriptions, APK metadata, a remediation checklist derived from the detected indicators, model metrics and drift, scan history, JSON export and print-to-PDF.
7. **Secure by default in Docker** — API-key auth with per-user task isolation, unguessable task IDs, upload rate limiting, size/type validation, hardened worker containers.
8. **Operable** — Alembic migrations, structured JSON logs with request IDs, Prometheus metrics, health checks, retention policy, SHA-256 result caching.

---

## 🛠 Tech Stack

| Layer | Technologies |
| :--- | :--- |
| **Frontend** | React 18, Vite, Recharts, react-markdown, Lucide, Vitest + Testing Library, nginx |
| **Backend API** | FastAPI, Uvicorn, Pydantic, SQLAlchemy 2, Alembic, prometheus-client |
| **Task queue** | Celery 5 (analysis + llm queues, beat), Redis |
| **Database** | PostgreSQL (Docker) or SQLite (local development) |
| **Static analysis** | Androguard 4 |
| **Machine learning** | LightGBM, scikit-learn (isotonic calibration), pandas, NumPy |
| **Explainable AI** | SHAP `TreeExplainer` |
| **Generative AI** | Google Gen AI SDK (`google-genai`) |
| **Tooling** | Docker Compose, GitHub Actions, ruff, ESLint, pre-commit, uv lockfile |

---

## 📂 Directory Structure

```text
BOI_prototype/
├── nexus_sec/                  # Backend package
│   ├── api.py                  # FastAPI app: /api/v1 routes, /health, /metrics
│   ├── security.py             # API-key auth, upload rate limiting
│   ├── schemas.py              # Pydantic response models
│   ├── worker.py               # Celery app, queues, beat schedule
│   ├── tasks.py                # analyze_apk, generate_llm_report, purge_expired
│   ├── extractor.py            # Androguard extraction + APK metadata
│   ├── features.py             # Drebin-215 feature matcher
│   ├── ml.py                   # Model bundle, calibrated scoring, SHAP, drift
│   ├── llm.py                  # Gemini prompt & client
│   ├── train.py                # python -m nexus_sec.train
│   ├── evaluate.py             # python -m nexus_sec.evaluate (new labelled data)
│   ├── evaluation.py           # Shared metrics / threshold selection
│   ├── metrics.py              # Prometheus metrics
│   ├── logging_config.py       # Text / JSON logs with request & task IDs
│   ├── models.py               # SQLAlchemy Task model
│   ├── database.py             # Engine & session factory
│   └── config.py               # Settings from environment / .env
├── alembic/                    # Database migrations
├── tests/                      # pytest suite
├── datasets/                   # Drebin-215 CSV + feature categories
├── models/                     # feature_names.json, metrics.json (+ generated malware_model.pkl)
├── frontend/                   # React dashboard (see frontend/README.md)
├── docs/ROADMAP.md             # Improvement plan and status
├── Dockerfile                  # Backend image (API, workers, beat)
├── docker-compose.yml          # Full stack
├── requirements.txt            # Direct dependencies
├── requirements.lock           # Pinned versions (uv pip compile)
├── requirements-dev.txt        # + pytest, ruff, pre-commit
└── pyproject.toml              # ruff & pytest configuration
```

---

## 🤖 Machine Learning & Dataset

The classifier is trained on **Drebin-215**: 215 binary static indicators across manifest permissions, API call signatures, intent actions and shell-command strings.

### Training pipeline (`python -m nexus_sec.train`)

1. **Deduplication.** The raw CSV has 15,036 rows but only 7,261 are unique; 6 more carry identical features with conflicting labels. Both are removed **before** splitting so no test sample is seen in training. (Earlier ~99 % figures were inflated by this leakage.)
2. **Split** 65 / 15 / 20 (train / validation / test), stratified.
3. **LightGBM** (300 trees, learning rate 0.05, `class_weight="balanced"`).
4. **Isotonic calibration** on the validation set, so the risk score is a real probability.
5. **Threshold** = lowest calibrated probability whose validation false-positive rate is ≤ `--max-fpr` (default 1 %).
6. Writes a **model bundle** (`models/malware_model.pkl`: model, calibrator, threshold, version) and `models/metrics.json` (test metrics, global SHAP importance, training feature prevalence for drift monitoring). The **version** is a content hash, so cached results are invalidated only when the model really changes.

### Current performance (held-out test set, 1,451 unique samples)

| Metric | Value |
| :--- | :--- |
| ROC AUC / PR AUC | 0.993 / 0.977 |
| Decision threshold | 0.625 |
| Malware precision / recall | 96.1 % / 93.3 % |
| False-positive rate | 1.2 % |

Figures are regenerated in `models/metrics.json` on every training run.

> **Limitations.** Drebin samples date from 2010–2012 and include no timestamps, so a temporal split is impossible and accuracy on modern malware will be lower. The dataset also has no family labels, so the system does not claim to identify malware families. Use `python -m nexus_sec.evaluate` to measure performance on newer labelled data:
>
> ```bash
> python -m nexus_sec.evaluate --csv new_samples.csv     # Drebin-schema CSV with class S/B
> python -m nexus_sec.evaluate --apk-dir samples/        # samples/malware/*.apk, samples/benign/*.apk
> ```

---

## 🐳 Quick Start (Docker)

Requires Docker with Compose v2.

```bash
cp .env.example .env          # optional: GEMINI_API_KEY, API_KEYS
docker compose up --build
```

Open **http://localhost:8080**. The backend image trains the model at build time, and the API container applies database migrations on start.

| Service | Role |
| :--- | :--- |
| `frontend` | nginx serving the dashboard and proxying `/api` |
| `api` | FastAPI (runs `alembic upgrade head` first) |
| `analysis-worker` | Androguard + model; internal network only |
| `llm-worker` | Gemini reports; the only service with internet egress |
| `beat` | Hourly retention clean-up |
| `postgres`, `redis` | Storage and queue |

---

## 💻 Local Development

Prerequisites: Python 3.10–3.12, Node.js 18+, Redis on `localhost:6379`.

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.lock -r requirements-dev.txt

python -m nexus_sec.train        # creates models/malware_model.pkl (~10 s)
alembic upgrade head             # creates/updates malware.db (SQLite)
cp .env.example .env             # add GEMINI_API_KEY for LLM reports

cd frontend && npm install && cd ..
```

Run in four terminals:

```bash
redis-server
celery -A nexus_sec.worker worker -Q analysis,llm -B --loglevel=info   # one worker, both queues + beat
uvicorn nexus_sec.api:app --reload --port 8000                          # http://127.0.0.1:8000/docs
cd frontend && npm run dev                                              # http://localhost:5173
```

> The worker uses Celery's `solo` pool to avoid fork deadlocks with LightGBM's OpenMP threads; this is configured in `nexus_sec/worker.py`.

Schema changes: edit `nexus_sec/models.py`, then `alembic revision --autogenerate -m "describe change"` and `alembic upgrade head`.

---

## 🔌 REST API Reference

Interactive docs: `http://127.0.0.1:8000/docs`. When `API_KEYS` is set, every `/api/v1` call needs an `X-API-Key` header, and each key only sees its own tasks.

### `POST /api/v1/tasks` — upload an APK

Multipart form field `file`. Only `.apk` files that are valid ZIP archives up to `MAX_UPLOAD_MB` are accepted.

```json
202 Accepted
{ "task_id": "3f6c1e0a-…", "status": "queued", "cached": false }
```

If an identical APK (same SHA-256) was already analysed by the current model version, the result is reused immediately (`"status": "completed", "cached": true`).

Errors: `400` invalid file · `401` missing/invalid key · `413` too large · `429` rate limited (see `Retry-After`) · `503` queue unavailable.

### `GET /api/v1/tasks/{task_id}` — scan status and results

Analysis status: `queued` → `processing` → `completed` | `failed`.
Report status (once completed): `pending` → `completed` | `skipped` | `failed`.

```json
{
  "task_id": "3f6c1e0a-…",
  "filename": "sample.apk",
  "status": "completed",
  "verdict": "malicious",
  "malware_score": 97.4,
  "model_version": "lgbm-068a2b0f7731",
  "sha256": "…",
  "shap_data": { "TelephonyManager.getDeviceId": 1.21, "SEND_SMS": 1.05 },
  "features": {
    "permissions": ["SEND_SMS", "READ_PHONE_STATE"],
    "api_calls": ["Ljava.lang.Class.forName", "Runtime.exec"],
    "intents": ["android.intent.action.BOOT_COMPLETED"],
    "commands": ["chmod"]
  },
  "apk_info": { "package": "com.example", "target_sdk": "28", "certificates": [], "...": "..." },
  "report_status": "completed",
  "llm_report": "## Executive Summary\n…",
  "error": null,
  "cached_from": null,
  "created_at": "2026-11-17T09:00:00Z",
  "updated_at": "2026-11-17T09:00:21Z",
  "completed_at": "2026-11-17T09:00:14Z"
}
```

### Other endpoints

| Endpoint | Description |
| :--- | :--- |
| `GET /api/v1/tasks?limit=20` | Your most recent scans |
| `GET /api/v1/model` | Model version, threshold, test metrics, global SHAP importance |
| `GET /api/v1/model/drift` | Indicator prevalence in recent scans vs. training data |
| `GET /health` | Database and queue reachability (`503` if either is down) |
| `GET /metrics` | Prometheus metrics |

---

## 🖥️ Frontend Dashboard

- **Sidebar** — drag-and-drop uploader with client-side type/size checks, API key field (kept in session storage), recent-scan history, JSON export and print-to-PDF.
- **Progress** — driven by the real task status; polls with backoff, no fixed timeout.
- **Summary** — calibrated malware probability, verdict against the model's threshold, indicator count, analysis time / cache status.
- **SHAP chart** — top attributions, marking whether each feature was present or contributed by its absence.
- **GenAI report** — rendered Markdown; shows pending / skipped / failed states without hiding the verdict.
- **Tabs** — detected indicators (with reference descriptions and SHAP values), APK metadata and certificates, remediation checklist derived from the verdict and indicators, model metrics and drift.
- **Demo** — "View a sample result" shows a clearly labelled sample. Failed or unreachable scans show an error; sample data is **never** substituted for a real result.

---

## 🔐 Security Model

| Control | Implementation |
| :--- | :--- |
| Authentication | `API_KEYS` (`name:key,…`); constant-time comparison. Empty = auth off (development only). |
| Authorization | Tasks belong to the uploading key; other users get `404`. |
| Unguessable IDs | Task IDs are random UUIDs. |
| Upload validation | `.apk` extension, ZIP magic bytes, streamed size cap, server-generated file names. |
| Rate limiting | `UPLOAD_RATE_LIMIT_PER_MINUTE` per key (or client IP). In-memory: per API process. |
| Worker isolation | Analysis worker: internal network only, read-only root FS, all capabilities dropped, `no-new-privileges`, memory/CPU/PID limits, non-root user. |
| LLM prompt hardening | Only matched feature names from the fixed 215-entry vocabulary reach the prompt — never APK strings, package or app names. |
| CORS | Explicit origin allow-list; Docker deployment is same-origin through nginx. |
| HTTP headers | CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer` (nginx). |
| Retention | Results older than `RESULT_RETENTION_DAYS` and orphaned uploads are purged hourly. |

---

## 📈 Operations

- **Logs** — `LOG_FORMAT=json` (default in Docker) emits one JSON object per line with `request_id` and `task_id`. Pass `X-Request-ID` to correlate a request through the API and both workers.
- **Metrics** — API `GET /metrics`; analysis worker on `WORKER_METRICS_PORT` (9100 in Docker). Key series: `nexus_uploads_total{outcome}`, `nexus_analyses_total{outcome}`, `nexus_analysis_duration_seconds`, `nexus_llm_reports_total{outcome}`, `nexus_tasks{status}`, `nexus_http_request_duration_seconds`.
- **Health** — `GET /health` checks database and Redis; used by the Compose healthcheck.
- **Drift** — the dashboard's *Model & drift* tab (or `GET /api/v1/model/drift`) compares indicator prevalence in recent distinct scans with the training data.

---

## ⚙️ Configuration & Environment Variables

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
| `UPLOAD_DIR` | Shared by API and analysis worker | `<repo>/uploads` |
| `MAX_UPLOAD_MB` | Maximum APK size | `100` |
| `CORS_ORIGINS` | Allowed browser origins | `http://localhost:5173,http://127.0.0.1:5173` |
| `ANALYSIS_TIME_LIMIT` | Seconds before an analysis is aborted | `600` |
| `RESULT_RETENTION_DAYS` | Delete results older than this (0 = keep) | `30` |
| `WORKER_METRICS_PORT` | Worker Prometheus port (0 = off) | `0` |
| `LOG_LEVEL` / `LOG_FORMAT` | Logging level / `text` or `json` | `INFO` / `text` |
| `MODEL_DIR` | Model bundle location | `<repo>/models` |

Frontend variables are listed in `frontend/.env.example`.

---

## 🧪 Testing & CI

```bash
pytest                       # backend: features, extractor, API, tasks, ML, migrations
ruff check .
cd frontend && npm test && npm run lint
pre-commit install           # optional: run ruff, eslint and hygiene hooks on commit
```

Backend tests need no Redis, Androguard sample, trained model or Gemini key. GitHub Actions (`.github/workflows/ci.yml`) runs lint, tests, a training smoke test, the frontend build and the Docker image build on every push and pull request.

---

## ❓ Troubleshooting & FAQ

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

---

## 🗺 Roadmap

See [`docs/ROADMAP.md`](docs/ROADMAP.md) for the phased improvement plan, what each phase delivered, and what remains.
