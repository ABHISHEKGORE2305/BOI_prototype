export const CATEGORY_LABELS = {
  permissions: 'Manifest permissions',
  api_calls: 'API calls & classes',
  intents: 'Intent actions',
  commands: 'Shell commands',
  other: 'Other',
};

export function riskLevel(score, verdict) {
  if (score == null) return { label: 'UNKNOWN', tone: 'muted' };
  if (verdict === 'malicious') {
    return score >= 90
      ? { label: 'CRITICAL RISK', tone: 'critical' }
      : { label: 'HIGH RISK', tone: 'high' };
  }
  return score >= 25
    ? { label: 'SUSPICIOUS — REVIEW', tone: 'medium' }
    : { label: 'LOW RISK', tone: 'clean' };
}

export function shortFeatureName(name, max = 32) {
  const short = name
    .replace(/^android\.intent\.action\./, 'intent:')
    .replace(/^Landroid\./, 'android.')
    .replace(/^Ljava\./, 'java.')
    .replace(/^Ljavax\./, 'javax.');
  return short.length > max ? `${short.slice(0, max - 1)}…` : short;
}

export function formatDuration(start, end) {
  if (!start || !end) return null;
  const seconds = (new Date(end) - new Date(start)) / 1000;
  if (!Number.isFinite(seconds) || seconds < 0) return null;
  if (seconds < 60) return `${seconds.toFixed(1)}s`;
  return `${Math.floor(seconds / 60)}m ${Math.round(seconds % 60)}s`;
}

export function formatDateTime(value) {
  if (!value) return '—';
  return new Date(value).toLocaleString();
}

export function countIndicators(features = {}) {
  return Object.values(features).reduce((sum, list) => sum + list.length, 0);
}
