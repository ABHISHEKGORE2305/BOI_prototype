import { render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { vi } from 'vitest';
import App from '../App';

const FAST_POLL = { initialDelay: 5, maxDelay: 5 };

const MODEL = {
  version: 'lgbm-test',
  trained_at: '2026-11-17T00:00:00+00:00',
  threshold: 0.625,
  max_fpr: 0.01,
  metrics: { roc_auc: 0.99, at_threshold: { precision: 0.96, recall: 0.93, false_positive_rate: 0.01 } },
  global_importance: [{ feature: 'SEND_SMS', importance: 0.5 }],
};

function completedTask(overrides = {}) {
  return {
    task_id: 't1',
    filename: 'sample.apk',
    status: 'completed',
    verdict: 'malicious',
    malware_score: 97.5,
    model_version: 'lgbm-test',
    created_at: '2026-11-17T10:00:00+00:00',
    completed_at: '2026-11-17T10:00:12+00:00',
    updated_at: '2026-11-17T10:00:12+00:00',
    sha256: 'ab'.repeat(32),
    shap_data: { SEND_SMS: 1.2, INTERNET: -0.3 },
    features: { permissions: ['SEND_SMS', 'INTERNET'], api_calls: [], intents: [], commands: [] },
    apk_info: { package: 'com.evil.app', permissions: [], component_counts: {} },
    report_status: 'completed',
    llm_report: '## Executive Summary\nThis app **steals SMS**.',
    error: null,
    cached_from: null,
    ...overrides,
  };
}

function json(body, status = 200) {
  return Promise.resolve(new Response(JSON.stringify(body), { status }));
}

/**
 * Route fetch calls by method + path. `taskResponses` are returned in order
 * for successive GET /tasks/:id polls (the last one repeats).
 */
function mockApi({ upload, taskResponses = [], model = MODEL } = {}) {
  let poll = 0;
  return vi.spyOn(globalThis, 'fetch').mockImplementation((url, options = {}) => {
    const path = String(url);
    if (options.method === 'POST' && path.endsWith('/api/v1/tasks')) return upload();
    if (path.includes('/api/v1/tasks/')) {
      const response = taskResponses[Math.min(poll, taskResponses.length - 1)];
      poll += 1;
      return response();
    }
    if (path.includes('/api/v1/tasks')) return json([]);
    if (path.endsWith('/api/v1/model')) return model ? json(model) : json({ detail: 'No trained model' }, 503);
    return json({ detail: 'unexpected' }, 500);
  });
}

const apkFile = () => new File(['PK\u0003\u0004data'], 'sample.apk', { type: 'application/vnd.android.package-archive' });

async function uploadSample() {
  const user = userEvent.setup();
  await user.upload(screen.getByLabelText('Upload APK file'), apkFile());
}

test('shows real results after the task completes, then the report', async () => {
  mockApi({
    upload: () => json({ task_id: 't1', status: 'queued', cached: false }, 202),
    taskResponses: [
      () => json({ ...completedTask(), status: 'queued', verdict: null, malware_score: null }),
      () => json(completedTask({ report_status: 'pending', llm_report: null })),
      () => json(completedTask()),
    ],
  });
  render(<App pollOptions={FAST_POLL} />);

  await uploadSample();

  expect(await screen.findByText('97.5/100')).toBeInTheDocument();
  expect(screen.getByText('Malicious')).toBeInTheDocument();
  expect(await screen.findByRole('heading', { name: 'Executive Summary' })).toBeInTheDocument();
  expect(screen.getByText('steals SMS')).toBeInTheDocument();
  expect(screen.queryByText(/Sample data/)).not.toBeInTheDocument();
});

test('a failed analysis shows the error, never fabricated results', async () => {
  mockApi({
    upload: () => json({ task_id: 't1', status: 'queued', cached: false }, 202),
    taskResponses: [() => json(completedTask({ status: 'failed', error: 'BadZipFile: corrupt', malware_score: null }))],
  });
  render(<App pollOptions={FAST_POLL} />);

  await uploadSample();

  expect(await screen.findByRole('alert')).toHaveTextContent('BadZipFile: corrupt');
  expect(screen.queryByText(/\/100/)).not.toBeInTheDocument();
  expect(screen.queryByText(/Sample data/)).not.toBeInTheDocument();
});

test('an unreachable backend shows a connection error instead of demo data', async () => {
  vi.spyOn(globalThis, 'fetch').mockRejectedValue(new TypeError('Failed to fetch'));
  render(<App pollOptions={FAST_POLL} />);

  await uploadSample();

  expect(await screen.findByRole('alert')).toHaveTextContent('Cannot reach the Nexus-Sec API');
  expect(screen.queryByText(/\/100/)).not.toBeInTheDocument();
});

test('rejects non-APK files before uploading', async () => {
  const fetchSpy = mockApi({ upload: () => json({}, 500) });
  render(<App pollOptions={FAST_POLL} />);
  const user = userEvent.setup({ applyAccept: false });

  await user.upload(screen.getByLabelText('Upload APK file'), new File(['x'], 'notes.txt'));

  expect(await screen.findByRole('alert')).toHaveTextContent('Only .apk files');
  expect(fetchSpy.mock.calls.some(([, options]) => options?.method === 'POST')).toBe(false);
});

test('API key errors explain how to fix them', async () => {
  mockApi({ upload: () => json({ detail: 'Invalid or missing API key' }, 401) });
  render(<App pollOptions={FAST_POLL} />);

  await uploadSample();

  expect(await screen.findByRole('alert')).toHaveTextContent('Enter it in the sidebar');
});

test('demo mode is opt-in and clearly labelled', async () => {
  mockApi({ upload: () => json({}, 500) });
  render(<App pollOptions={FAST_POLL} />);
  const user = userEvent.setup();

  expect(screen.queryByText(/Sample data/)).not.toBeInTheDocument();
  await user.click(screen.getByRole('button', { name: /View a sample result/ }));

  expect(screen.getByText(/Sample data for illustration only/)).toBeInTheDocument();
  // Exports are only offered for real scans
  expect(screen.getByRole('button', { name: /Download raw JSON/ })).toBeDisabled();
});

test('LLM failure keeps the verdict visible', async () => {
  mockApi({
    upload: () => json({ task_id: 't1', status: 'queued', cached: false }, 202),
    taskResponses: [() => json(completedTask({ report_status: 'failed', llm_report: null }))],
  });
  render(<App pollOptions={FAST_POLL} />);

  await uploadSample();

  expect(await screen.findByText(/could not be generated/)).toBeInTheDocument();
  expect(screen.getByText('97.5/100')).toBeInTheDocument();
});

test('the API key is sent with requests once saved', async () => {
  const fetchSpy = mockApi({ upload: () => json({}, 500) });
  render(<App pollOptions={FAST_POLL} />);
  const user = userEvent.setup();

  await user.type(screen.getByLabelText(/server requires one/), 'secret-key');
  await user.click(screen.getByRole('button', { name: 'Save API key' }));

  await waitFor(() => {
    const keyed = fetchSpy.mock.calls.filter(([, options]) => options?.headers?.get('X-API-Key') === 'secret-key');
    expect(keyed.length).toBeGreaterThan(0);
  });
  expect(sessionStorage.getItem('nexus-sec-api-key')).toBe('secret-key');
});
