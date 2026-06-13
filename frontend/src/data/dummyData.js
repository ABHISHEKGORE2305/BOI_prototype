// ==========================================
// NEXUS-SEC APK THREAT INTEL MOCK DATA
// ==========================================

// # DUMMY DATA
export const DUMMY_MALWARE_FAMILY = "Trojan.Banker.AndroidOS";

// # DUMMY DATA
export const DUMMY_ANALYSIS_TIME = "1.4s";

// # DUMMY DATA
export const DUMMY_SHAP_DATA = {
  "android.permission.SEND_SMS": 1.45,
  "android.permission.READ_CONTACTS": 0.88,
  "android.permission.RECEIVE_BOOT_COMPLETED": 0.62,
  "Ljava.lang.Runtime.getRuntime": 0.54,
  "Ljava.lang.System.loadLibrary": 0.48,
  "android.permission.WRITE_SETTINGS": 0.35,
  "android.permission.ACCESS_FINE_LOCATION": -0.22,
  "android.permission.INTERNET": -0.15,
  "android.permission.CAMERA": -0.08,
  "android.permission.VIBRATE": -0.05
};

// # DUMMY DATA
export const DUMMY_LLM_REPORT = `### Executive Summary
The security pipeline has flagged this APK application as **High Risk**. Deep neural signatures and feature weights indicate patterns corresponding to financial credential exfiltration. The binary holds active privileges to capture SMS broadcasts and system boot events, facilitating persistence and background operation.

### Key Findings
- **SMS Interception Capability**: Multiple filters registered for \`SMS_RECEIVED\` events, bypassing multifactor authorization tokens.
- **Obfuscation & Dynamic Class Loading**: Use of system libraries and dynamic classes to evade automated static check patterns.
- **Critical Intents**: Autostart enabled via \`BOOT_COMPLETED\` intents.

### Explainability Insights
Machine learning classification was heavily influenced by the presence of \`SEND_SMS\` (45% impact delta) and \`READ_CONTACTS\`. Negative contributions from safe permissions like standard \`VIBRATE\` or standard \`CAMERA\` were negligible, leaving the final decision securely in the high-malicious region.`;

// # DUMMY DATA
export const DUMMY_PERMISSIONS = [
  { permission: "android.permission.SEND_SMS", riskLevel: "CRITICAL", description: "Allows sending SMS without user confirmation" },
  { permission: "android.permission.READ_CONTACTS", riskLevel: "HIGH", description: "Allows reading user's address book contacts" },
  { permission: "android.permission.RECEIVE_BOOT_COMPLETED", riskLevel: "MEDIUM", description: "Starts execution logic immediately after boot" },
  { permission: "android.permission.SYSTEM_ALERT_WINDOW", riskLevel: "HIGH", description: "Renders overlays on top of victim applications" },
  { permission: "android.permission.INSTALL_PACKAGES", riskLevel: "CRITICAL", description: "Downloads and installs secondary malicious packages" }
];

// # DUMMY DATA
export const DUMMY_IOCS = [
  { indicator: "http://193.161.193.99/payload.bin", type: "URL/Payload", reputation: "MALICIOUS", details: "Active C2 server distributing banker payloads" },
  { indicator: "85.25.103.111", type: "IP Address", reputation: "MALICIOUS", details: "Flagged by Spamhaus & AlienVault as active malware host" },
  { indicator: "https://google.com/generate_204", type: "URL/Ping", reputation: "CLEAN", details: "Connectivity verification endpoint" },
  { indicator: "http://api.telegram.org/bot6822...", type: "URL/API", reputation: "SUSPICIOUS", details: "Exfiltration using Telegram bot channel" }
];

// # DUMMY DATA
export const DUMMY_INTENTS = [
  { intentFilter: "android.intent.action.BOOT_COMPLETED", targetClass: "com.security.service.AutoStartReceiver", risk: "HIGH" },
  { intentFilter: "android.provider.Telephony.SMS_RECEIVED", targetClass: "com.security.service.SmsMonitor", risk: "CRITICAL" },
  { intentFilter: "android.intent.action.USER_PRESENT", targetClass: "com.security.service.UserActivityReceiver", risk: "MEDIUM" }
];

// # DUMMY DATA
export const DUMMY_REMEDIATION_STEPS = [
  "Block target C2 server IP address (85.25.103.111) on boundary firewalls.",
  "Revoke SMS and Accessibility permissions on active MDM agent profiles.",
  "Isolate the infected device to a secure quarantine VLAN.",
  "Issue remote data wipe trigger for critical credentials on target device.",
  "Push IOC definitions to corporate endpoint protection platforms."
];

// # DUMMY DATA
export const DUMMY_SYSTEM_LOGS = `2026-06-13 15:48:10 [celery-worker-1] INFO: Received task analyze_apk[428cb20d-7d84-482a-bc9a-653a9df8ba32]
2026-06-13 15:48:10 [celery-worker-1] INFO: Initiating Androguard analysis for /tmp/uploads/file.apk
2026-06-13 15:48:11 [androguard] INFO: Manifest decompiled successfully. Loaded 5 active permissions.
2026-06-13 15:48:11 [celery-worker-1] INFO: Executing feature builder... Vector generated: shape (1, 215)
2026-06-13 15:48:11 [celery-worker-1] INFO: Matched 8 / 215 feature identifiers in model vocabulary.
2026-06-13 15:48:11 [celery-worker-1] INFO: LightGBM Predict: probability = 0.88125
2026-06-13 15:48:11 [shap] INFO: TreeExplainer baseline initialized. Calculating Shapley additive values...
2026-06-13 15:48:12 [shap] INFO: SHAP value matrix complete (time elapsed: 245ms)
2026-06-13 15:48:12 [gemini-api] INFO: Request sent to gemini-2.5-flash model. Prompt tokens: 345
2026-06-13 15:48:13 [gemini-api] INFO: Response received. Generation time: 1.15s, tokens: 288
2026-06-13 15:48:13 [celery-worker-1] INFO: Writing task results to malware.db...
2026-06-13 15:48:13 [celery-worker-1] INFO: Task 428cb20d-7d84-482a-bc9a-653a9df8ba32 status set to COMPLETED.
2026-06-13 15:48:13 [celery-worker-1] INFO: Temp file cleanup: deleted /tmp/uploads/file.apk
2026-06-13 15:48:13 [kafka-producer] INFO: Publishing analysis results to topic 'apk-threat-events'... Offset: 48102
2026-06-13 15:48:13 [bentoml-service] INFO: Model inference endpoint response time: 48.2ms`;

// # DUMMY DATA
export const DUMMY_PDF_CONTENT = "%PDF-1.4 ... (Mock Nexus-Sec Malware Analysis Report PDF)";

// # DUMMY DATA
export const DUMMY_JSON_EXPORT = '{"analysis_engine": "Nexus-Sec v2.1", "status": "malicious", "risk_score": 88}';
