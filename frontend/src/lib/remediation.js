import { hasIndicator } from './indicators';

const SMS = [
  'SEND_SMS', 'RECEIVE_SMS', 'READ_SMS', 'android.telephony.SmsManager',
  'android.telephony.gsm.SmsManager', 'sendMultipartTextMessage', 'abortBroadcast',
];
const IDENTIFIERS = [
  'READ_PHONE_STATE', 'TelephonyManager.getDeviceId', 'TelephonyManager.getSubscriberId',
  'TelephonyManager.getLine1Number', 'TelephonyManager.getSimSerialNumber',
];
const DYNAMIC_CODE = ['DexClassLoader', 'PathClassLoader', 'URLClassLoader', 'defineClass'];
const ROOT_TOOLS = [
  'Runtime.exec', 'createSubprocess', 'chmod', 'chown', 'mount', 'remount', '/system/bin',
  '/system/app',
];
const PERSISTENCE = ['RECEIVE_BOOT_COMPLETED', 'android.intent.action.BOOT_COMPLETED'];

/**
 * Remediation steps derived from the scan's verdict and detected indicators.
 */
export function remediationSteps(task) {
  if (!task || task.status !== 'completed') return [];

  const features = task.features || {};
  const pkg = task.apk_info?.package;
  const sha = task.sha256;
  const steps = [];

  if (task.verdict !== 'malicious') {
    steps.push('No blocking action required by the classifier verdict; keep the result for audit.');
    if (DYNAMIC_CODE.some((f) => hasIndicator(features, [f]))) {
      steps.push(
        'The app loads code at run time, which static analysis cannot see. Run it in a dynamic-analysis sandbox before approving it.',
      );
    }
    steps.push('If the app arrived through an unusual channel (SMS link, side-loading), escalate for manual review regardless of score.');
    return steps;
  }

  steps.push(
    pkg
      ? `Block package ${pkg} in your MDM / app allow-list policy.`
      : 'Block this application in your MDM / app allow-list policy.',
  );
  if (sha) {
    steps.push(`Search device and EDR inventory for SHA-256 ${sha.slice(0, 16)}… to find affected devices.`);
  }
  steps.push('Isolate affected devices from corporate networks until they are remediated.');

  if (hasIndicator(features, SMS)) {
    steps.push('SMS capabilities detected: rotate credentials protected by SMS one-time codes and move users to app-based or hardware 2FA.');
  }
  if (hasIndicator(features, IDENTIFIERS)) {
    steps.push('Device identifiers may have been collected: watch for SIM-swap and account-takeover attempts against affected users.');
  }
  if (hasIndicator(features, PERSISTENCE)) {
    steps.push('The app restarts at boot: uninstall it (force-stop is not enough) and confirm removal after a reboot.');
  }
  if (hasIndicator(features, ROOT_TOOLS)) {
    steps.push('Shell / root tooling detected: check device integrity (Play Integrity / root detection); re-image devices that fail.');
  }
  if (hasIndicator(features, DYNAMIC_CODE)) {
    steps.push('Run-time code loading detected: detonate the sample in a sandbox to capture second-stage payloads and network IOCs.');
  }

  steps.push('Submit the SHA-256 to your threat-intelligence platform and share IOCs with the SOC.');
  return steps;
}
