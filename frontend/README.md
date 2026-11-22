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

- **Start screen** — drag-and-drop upload with client-side type/size checks. Upload errors keep the drop zone on screen so you can retry.
- **Progress** — driven by the real task status; polls with backoff, no fixed timeout.
- **Verdict** — calibrated malware probability on a 0–100 ruler showing the model's decision threshold, plus indicators matched, analysis time and model version.
- **Why the model decided this** — diverging SHAP bars (plain HTML/CSS), marking whether each indicator was present or counted by its absence.
- **Analyst report** — rendered Markdown; pending, skipped and failed states never hide the verdict.
- **Tabs** — indicators with reference descriptions and SHAP values, app details and certificates, a response checklist, model metrics and drift.
- **Exports** — Download JSON and a print stylesheet for Print report (real scans only).
- **Demo** — "View a sample result" shows a clearly labelled sample. Failed or unreachable scans show an error; sample data is **never** substituted for a real result.

## Design

A case-file layout: one white report sheet per scan on a cool grey page. Red, amber and green are reserved for the verdict, and indigo marks things you can act on. Type is Atkinson Hyperlegible Next with its Mono companion for identifiers, chosen because analysts read SHA-256 hashes and Java signatures where 0/O and 1/l/I must not be confused. Fonts are self-hosted (`@fontsource-variable`), so nginx's CSP allows no third-party origins. Dark mode follows the system setting; reduced motion is respected.

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
