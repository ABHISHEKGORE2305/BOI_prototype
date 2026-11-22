# Nexus-Sec Improvement Roadmap

Findings from a full-repo review, grouped into phases, with what each phase
delivered. Items that could not be completed are listed at the end with the reason.

---

## Phase 1 — Core pipeline correctness & reliability ✅

| # | Problem | Fix |
|---|---------|-----|
| 1.1 | **Feature extraction missed most of the 215 Drebin features.** The schema mixes naming styles (`transact`, `DexClassLoader`, `android.os.Binder`, `Ljava.lang.Class.forName`, `TelephonyManager.getDeviceId`, `HttpGet.init`, `chmod`, intent actions); extraction stripped the leading `L`, never emitted class / `Short.method` / `<init>` tokens, ignored DEX strings and only read receiver intent filters. On a real APK: **25 → 47 features matched**. `Ljava.lang.Class.getCanonicalName`, never detected before, is the model's 2nd most important feature. | Category-aware matcher (`nexus_sec/features.py`) + extractor (`nexus_sec/extractor.py`). |
| 1.2 | **Inflated metrics.** 15,036 rows but only 7,261 unique; the random split leaked duplicates into the test set. | Dedup + conflicting-label removal before splitting (`nexus_sec/train.py`). |
| 1.3 | API couldn't start without the ML stack + model file. | API enqueues by task name; worker loads the model lazily. |
| 1.4 | Hard-coded config. | `nexus_sec/config.py` from env / `.env`. |
| 1.5 | Unsafe uploads (no size/type check, client filename on disk, blocking I/O in `async def`). | Validation, streamed size cap, generated names, threadpool endpoints. |
| 1.6 | Enqueue failure left tasks stuck in `processing`. | Marked `failed`, file removed, `503`. |
| 1.7 | `allow_origins=["*"]` with credentials. | Origin allow-list. |
| 1.8 | Failures invisible. | `error`, timestamps, matched features stored; explicit status lifecycle. |
| 1.9 | Whole API-call set pasted into the LLM prompt; deprecated SDK. | Matched features only; `google-genai`. |
| 1.10 | No time limits (Celery's aren't enforced by the `solo` pool). | Per-task `ANALYSIS_TIME_LIMIT` via `SIGALRM`. |
| 1.11 | Side-effect "test" scripts, unpinned / unused deps. | pytest suite, cleaned requirements. |

## Phase 2 — Frontend truthfulness & wiring ✅

- Sample data is **never** substituted for a real scan. Failures, timeouts, `401`/`429`/`413` and an unreachable backend show specific errors; demo mode is an explicit, bannered choice.
- Progress stepper follows real task status; polling backs off (1 → 5 s) with no 30 s cutoff and gives up only after 30 min.
- Real indicators, APK metadata, SHAP values and model info replace `DUMMY_*` tables; removed fake controls (LLM selector, depth slider), fake malware family, fake logs, fake host name.
- Real JSON export (actual result) and print-to-PDF with a print stylesheet.
- `react-markdown` + GFM for reports; explicit pending / skipped / failed report states.
- `/api/v1` via Vite dev proxy / nginx (same-origin); `VITE_API_URL` override.
- 685-line `App.jsx` split into `components/`, `hooks/`, `lib/`; inline styles moved to CSS.
- Real drag-and-drop, client-side type/size checks, ARIA tabs/live regions, focus styles, responsive layout, reduced-motion support.
- Remediation checklist derived from the verdict and detected indicators.

## Phase 3 — Engineering foundations ✅

- Backend package `nexus_sec/` (kept at the repo root rather than `backend/` to keep commands short); Pydantic response models; `/api/v1` prefix.
- Alembic migrations (`alembic upgrade head`), with a test that migrations match the models.
- `Dockerfile` (non-root, model trained at build) and `docker-compose.yml` (postgres, redis, api, analysis-worker, llm-worker, beat, nginx frontend).
- GitHub Actions: ruff, pytest, training smoke test, ESLint, Vitest, Vite build, Docker build.
- ruff config (`pyproject.toml`), pre-commit hooks, `requirements.lock` (uv, universal).
- Frontend tests (Vitest + Testing Library) for upload / poll / error / demo / API-key flows.

## Phase 4 — Security & operations ✅

- API-key auth (`API_KEYS`), per-key task ownership, random UUID task IDs.
- Upload rate limiting (`429` + `Retry-After`): a Redis sliding window (atomic Lua script on the server clock) shared across API replicas, failing open if Redis is unavailable.
- SHA-256 result cache, keyed by model version.
- Analysis worker isolated: internal-only network, read-only FS, no capabilities, resource limits. The LLM step runs in a separate worker that never mounts uploads.
- Classification and LLM report split into separate tasks/queues; report retried with exponential backoff, and a Gemini outage never blocks a verdict.
- JSON logs with request/task IDs (propagated API → workers), Prometheus metrics (API + worker), `/health` checking DB and Redis.
- Hourly retention purge of old results and orphaned uploads (Celery beat).
- Prompt-injection hardening: only schema-vocabulary feature names reach the LLM, wrapped as data with a system instruction.
- nginx security headers (CSP, frame denial, nosniff).

## Phase 5 — ML quality ✅ (tooling) / ⏳ (data-dependent items)

- Isotonic probability calibration; decision threshold tuned to a false-positive budget (`--max-fpr`, default 1 %).
- Model bundle with content-hash version, stored on every task; cache invalidates on model change.
- Global SHAP importance and training feature prevalence in `models/metrics.json`; `/api/v1/model` and `/api/v1/model/drift` endpoints plus dashboard tab.
- `python -m nexus_sec.evaluate` scores the model on new labelled CSVs or APK folders.
- Extra analyst metadata (certificates, SDK levels, native libraries, debuggable flag, signature schemes) extracted and displayed. It is deliberately **not** fed to the model, which can only use the 215 Drebin features it was trained on.
- Notebook and unused `label_encoder.pkl` retired in favour of `train.py`.

## Phase 6 — Portfolio polish ✅

- `api.py` (447 lines) split into `routers/` (thin HTTP handlers) and `services/` (uploads, result cache, enqueueing).
- Redis sliding-window rate limiter shared by all API replicas (see Phase 4).
- End-to-end tests: generated APKs with a compiled binary manifest go through the API and the real Celery pipeline. No malware samples in the repo.
- Tests for training (dedup, artifacts, deterministic versions) and evaluation; branch coverage 80% → 90% with an 85% CI floor and Codecov upload.
- Lazy-loaded dashboard: initial JS 216 kB → 54 kB gzipped.
- README cut to an overview; reference material moved to `docs/API.md`, `docs/SECURITY.md`, `docs/OPERATIONS.md`.

---

## Not done, and why

| Item | Reason / next step |
|------|--------------------|
| Evaluate on modern samples (AndroZoo, CIC-AndMal) | Needs a dataset (AndroZoo requires an API key). Tooling is ready: `python -m nexus_sec.evaluate --apk-dir …`. |
| Temporal split | Drebin rows have no timestamps. Needs a dated dataset. |
| Features beyond the Drebin 215 | Needs training data containing those features; the metadata is already extracted for when it exists. |
| Malware-family classification | The dataset has no family labels; the old UI's family name was hard-coded. |
| Dataset in Git LFS | 6 MB is within normal git limits; moving it would rewrite history for all clones. Revisit if more datasets are added. |
| Domain-restricted LLM egress | The `llm-worker` has general internet egress; restrict to Google's API endpoints with an egress proxy in production. |
| Secrets management | Keys come from env / `.env`; use a secrets manager (Vault, cloud KMS) in production. |
