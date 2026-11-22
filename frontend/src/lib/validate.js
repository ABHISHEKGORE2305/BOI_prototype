import { MAX_UPLOAD_MB } from '../api';

export function validateApk(file) {
  if (!file.name.toLowerCase().endsWith('.apk')) return 'Only .apk files can be analysed.';
  if (file.size === 0) return 'The selected file is empty.';
  if (file.size > MAX_UPLOAD_MB * 1024 * 1024) return `File exceeds the ${MAX_UPLOAD_MB} MB limit.`;
  return null;
}
