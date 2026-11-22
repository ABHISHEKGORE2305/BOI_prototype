# Nexus-Sec dashboard

React 18 + Vite client for the Nexus-Sec API. See the [root README](../README.md) for the full system.

```bash
npm install
npm run dev      # http://localhost:5173, proxies /api to http://127.0.0.1:8000
npm test         # Vitest + Testing Library
npm run lint
npm run build
```

Configuration (`.env`, see `.env.example`): `VITE_API_URL`, `VITE_PROXY_TARGET`, `VITE_MAX_UPLOAD_MB`.

## Features

- **Sidebar** — drag-and-drop uploader with client-side type/size checks, API key field (kept in session storage), recent-scan history, JSON export and print-to-PDF.
- **Progress** — driven by the real task status; polls with backoff, no fixed timeout.
- **Summary** — calibrated malware probability, verdict against the model's threshold, indicator count, analysis time / cache status.
- **SHAP chart** — top attributions, marking whether each feature was present or contributed by its absence.
- **GenAI report** — rendered Markdown; shows pending / skipped / failed states without hiding the verdict.
- **Tabs** — detected indicators (with reference descriptions and SHAP values), APK metadata and certificates, remediation checklist derived from the verdict and indicators, model metrics and drift.
- **Demo** — "View a sample result" shows a clearly labelled sample. Failed or unreachable scans show an error; sample data is **never** substituted for a real result.

## Layout

```text
src/
├── App.jsx                 # Upload → poll → result state machine
├── api.js                  # REST client (/api/v1), error messages
├── hooks/useTaskPolling.js # Polls a task with backoff until analysis + report settle
├── components/             # Sidebar, Uploader, PipelineProgress, Dashboard and its panels
├── lib/                    # Formatting, indicator reference text, remediation rules, validation
├── data/demoResult.js      # Sample result shown only via "View a sample result"
└── test/                   # Vitest suites
```

The dashboard never substitutes sample data for a real scan: failures and timeouts show an
error, and demo mode is an explicit, labelled choice.
