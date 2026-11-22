// Illustrative sample result, shaped exactly like GET /api/v1/tasks/:id.
// Only ever shown when the user explicitly opens the demo, with a banner.

export const DEMO_TASK = {
  task_id: 'demo',
  filename: 'demo-banking-trojan.apk',
  status: 'completed',
  verdict: 'malicious',
  malware_score: 96.4,
  created_at: '2026-01-01T12:00:00+00:00',
  completed_at: '2026-01-01T12:00:14+00:00',
  updated_at: '2026-01-01T12:00:21+00:00',
  sha256: '0000000000000000000000000000000000000000000000000000000000000000',
  model_version: 'demo',
  cached_from: null,
  error: null,
  shap_data: {
    'TelephonyManager.getDeviceId': 1.21,
    SEND_SMS: 1.05,
    RECEIVE_SMS: 0.74,
    'Ljava.lang.Class.getCanonicalName': -0.52,
    DexClassLoader: 0.48,
    'android.intent.action.BOOT_COMPLETED': 0.41,
    transact: -0.33,
    abortBroadcast: 0.29,
    INTERNET: -0.12,
    chmod: 0.11,
  },
  features: {
    permissions: ['SEND_SMS', 'RECEIVE_SMS', 'READ_SMS', 'READ_PHONE_STATE', 'RECEIVE_BOOT_COMPLETED', 'INTERNET'],
    api_calls: ['TelephonyManager.getDeviceId', 'DexClassLoader', 'abortBroadcast', 'android.telephony.SmsManager'],
    intents: ['android.intent.action.BOOT_COMPLETED'],
    commands: ['chmod'],
  },
  apk_info: {
    package: 'com.example.demo.banker',
    app_name: 'Demo Banker',
    version_name: '1.0',
    version_code: '1',
    min_sdk: '21',
    target_sdk: '28',
    debuggable: false,
    permissions: [
      'android.permission.INTERNET',
      'android.permission.READ_PHONE_STATE',
      'android.permission.READ_SMS',
      'android.permission.RECEIVE_BOOT_COMPLETED',
      'android.permission.RECEIVE_SMS',
      'android.permission.SEND_SMS',
    ],
    component_counts: { activities: 3, services: 2, receivers: 2, providers: 0 },
    dex_files: 1,
    native_libraries: [],
    signature_schemes: ['v1'],
    certificates: [
      {
        subject: 'Common Name: Demo',
        issuer: 'Common Name: Demo',
        sha256: '00'.repeat(32),
        self_signed: 'maybe',
        not_after: '2050-01-01T00:00:00+00:00',
      },
    ],
  },
  report_status: 'completed',
  llm_report: `## Executive Summary
This is **sample output** illustrating the report format. The demo APK requests SMS send/receive permissions, reads the device identifier and registers for boot, a combination typical of SMS-stealing banking trojans.

## Threat Classification
- **Category:** Banking trojan / SMS stealer (illustrative)

## Recommended Actions
1. Block the package in MDM.
2. Rotate SMS-based 2FA for affected users.
`,
};
