# Security Model

| Control | Implementation |
| :--- | :--- |
| Authentication | `API_KEYS` (`name:key,…`); constant-time comparison. Empty = auth off (development only). |
| Authorization | Tasks belong to the uploading key; other users get `404`. |
| Unguessable IDs | Task IDs are random UUIDs. |
| Upload validation | `.apk` extension, ZIP magic bytes, streamed size cap, server-generated file names. |
| Rate limiting | `UPLOAD_RATE_LIMIT_PER_MINUTE` per key (or client IP). Sliding window in Redis (atomic Lua script, server clock), shared across API replicas; fails open if Redis is down. `RATE_LIMIT_BACKEND=memory` for a single process. |
| Worker isolation | Analysis worker: internal network only, read-only root FS, all capabilities dropped, `no-new-privileges`, memory/CPU/PID limits, non-root user. |
| LLM prompt hardening | Only matched feature names from the fixed 215-entry vocabulary reach the prompt — never APK strings, package or app names. |
| CORS | Explicit origin allow-list; Docker deployment is same-origin through nginx. |
| HTTP headers | CSP, `X-Frame-Options: DENY`, `nosniff`, `no-referrer` (nginx). |
| Retention | Results older than `RESULT_RETENTION_DAYS` and orphaned uploads are purged hourly. |

Items deliberately left for a production deployment (egress restriction for the LLM worker, a secrets manager) are listed in [ROADMAP.md](ROADMAP.md#not-done-and-why).
