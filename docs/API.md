# REST API Reference

Interactive docs: `http://127.0.0.1:8000/docs`. When `API_KEYS` is set, every `/api/v1` call needs an `X-API-Key` header, and each key only sees its own tasks.

## `POST /api/v1/tasks` — upload an APK

Multipart form field `file`. Only `.apk` files that are valid ZIP archives up to `MAX_UPLOAD_MB` are accepted.

```json
202 Accepted
{ "task_id": "3f6c1e0a-…", "status": "queued", "cached": false }
```

If an identical APK (same SHA-256) was already analysed by the current model version, the result is reused immediately (`"status": "completed", "cached": true`).

Errors: `400` invalid file · `401` missing/invalid key · `413` too large · `429` rate limited (see `Retry-After`) · `503` queue unavailable.

## `GET /api/v1/tasks/{task_id}` — scan status and results

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

## Other endpoints

| Endpoint | Description |
| :--- | :--- |
| `GET /api/v1/tasks?limit=20` | Your most recent scans |
| `GET /api/v1/model` | Model version, threshold, test metrics, global SHAP importance |
| `GET /api/v1/model/drift` | Indicator prevalence in recent scans vs. training data |
| `GET /health` | Database and queue reachability (`503` if either is down) |
| `GET /metrics` | Prometheus metrics |
