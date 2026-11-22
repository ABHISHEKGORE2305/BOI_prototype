// Reference descriptions for notable Drebin indicators. These explain what a
// feature *can* be used for; they are not evidence that this APK does so.

const HIGH = 'high';
const MEDIUM = 'medium';

const INDICATORS = {
  SEND_SMS: [HIGH, 'Send SMS without user interaction (premium-rate fraud, worm spreading).'],
  RECEIVE_SMS: [HIGH, 'Read incoming SMS as they arrive (OTP / 2FA interception).'],
  READ_SMS: [HIGH, 'Read stored SMS messages.'],
  WRITE_SMS: [MEDIUM, 'Modify or delete SMS (hiding evidence of fraud).'],
  READ_PHONE_STATE: [MEDIUM, 'Access device identifiers and call state.'],
  CALL_PHONE: [HIGH, 'Place calls without user confirmation.'],
  PROCESS_OUTGOING_CALLS: [HIGH, 'Monitor or redirect outgoing calls.'],
  READ_CONTACTS: [MEDIUM, 'Read the address book.'],
  RECEIVE_BOOT_COMPLETED: [MEDIUM, 'Start automatically after reboot (persistence).'],
  SYSTEM_ALERT_WINDOW: [HIGH, 'Draw overlays over other apps (credential phishing).'],
  INSTALL_PACKAGES: [HIGH, 'Install further packages.'],
  DELETE_PACKAGES: [HIGH, 'Uninstall other packages.'],
  GET_ACCOUNTS: [MEDIUM, 'List accounts registered on the device.'],
  'TelephonyManager.getDeviceId': [MEDIUM, 'Reads the IMEI/MEID device identifier.'],
  'TelephonyManager.getSubscriberId': [MEDIUM, 'Reads the IMSI subscriber identifier.'],
  'TelephonyManager.getLine1Number': [MEDIUM, 'Reads the device phone number.'],
  'TelephonyManager.getSimSerialNumber': [MEDIUM, 'Reads the SIM serial number.'],
  'android.telephony.SmsManager': [HIGH, 'Programmatic SMS sending.'],
  sendMultipartTextMessage: [HIGH, 'Sends long SMS messages programmatically.'],
  abortBroadcast: [HIGH, 'Suppresses broadcasts, e.g. hiding incoming SMS from the user.'],
  DexClassLoader: [HIGH, 'Loads code at run time — payloads may be downloaded later.'],
  PathClassLoader: [MEDIUM, 'Loads classes from file paths at run time.'],
  'System.loadLibrary': [MEDIUM, 'Loads native code.'],
  'Runtime.exec': [HIGH, 'Executes shell commands.'],
  'Runtime.getRuntime': [MEDIUM, 'Gets the runtime, typically to execute commands.'],
  'Ljava.lang.Class.forName': [MEDIUM, 'Reflection — can hide which APIs are called.'],
  createSubprocess: [HIGH, 'Spawns native subprocesses.'],
  'Ljavax.crypto.Cipher': [MEDIUM, 'Encryption — legitimate, but also used to hide payloads.'],
  chmod: [HIGH, 'Changes file permissions, often to make dropped binaries executable.'],
  mount: [HIGH, 'Remounts file systems, typical of rooting exploits.'],
  remount: [HIGH, 'Remounts /system read-write, typical of rooting exploits.'],
  chown: [HIGH, 'Changes file ownership.'],
  '/system/bin': [MEDIUM, 'References system binaries.'],
  '/system/app': [HIGH, 'References the system app partition (persistence as a system app).'],
  'android.intent.action.BOOT_COMPLETED': [MEDIUM, 'Runs at boot (persistence).'],
  'android.intent.action.NEW_OUTGOING_CALL': [HIGH, 'Observes outgoing calls.'],
  'android.intent.action.PACKAGE_ADDED': [MEDIUM, 'Watches for newly installed apps.'],
};

export function describeIndicator(feature) {
  const entry = INDICATORS[feature];
  return entry ? { level: entry[0], description: entry[1] } : { level: null, description: null };
}

export const hasIndicator = (features, names) =>
  Object.values(features || {}).some((list) => list.some((f) => names.includes(f)));
