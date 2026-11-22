// Client for the Nexus-Sec REST API (/api/v1).
//
// In development Vite proxies /api to the FastAPI server (vite.config.js);
// in Docker nginx does. Set VITE_API_URL to call a different origin.

const BASE_URL = (import.meta.env.VITE_API_URL || '/api/v1').replace(/\/$/, '');

export const MAX_UPLOAD_MB = Number(import.meta.env.VITE_MAX_UPLOAD_MB || 100);

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function messageFor(status, detail, response) {
  switch (status) {
    case 401:
      return 'This server requires a valid API key. Enter it in the sidebar.';
    case 404:
      return detail || 'Not found.';
    case 429: {
      const retryAfter = response.headers.get('Retry-After');
      return `Upload rate limit reached.${retryAfter ? ` Try again in ${retryAfter}s.` : ''}`;
    }
    case 503:
      return detail || 'The analysis service is temporarily unavailable.';
    default:
      return detail || `Request failed (HTTP ${status}).`;
  }
}

async function request(path, { apiKey, ...options } = {}) {
  const headers = new Headers(options.headers);
  if (apiKey) headers.set('X-API-Key', apiKey);

  let response;
  try {
    response = await fetch(`${BASE_URL}${path}`, { ...options, headers });
  } catch {
    throw new ApiError('Cannot reach the Nexus-Sec API. Is the backend running?', 0);
  }

  if (!response.ok) {
    let detail;
    try {
      detail = (await response.json()).detail;
    } catch {
      // Non-JSON error body (e.g. proxy error page)
    }
    if (typeof detail !== 'string') detail = undefined;
    throw new ApiError(messageFor(response.status, detail, response), response.status);
  }

  return response.json();
}

export function uploadApk(file, apiKey) {
  const body = new FormData();
  body.append('file', file);
  return request('/tasks', { method: 'POST', body, apiKey });
}

export const getTask = (taskId, apiKey) =>
  request(`/tasks/${encodeURIComponent(taskId)}`, { apiKey });

export const listTasks = (apiKey, limit = 15) => request(`/tasks?limit=${limit}`, { apiKey });

export const getModelInfo = (apiKey) => request('/model', { apiKey });

export const getDrift = (apiKey) => request('/model/drift', { apiKey });
