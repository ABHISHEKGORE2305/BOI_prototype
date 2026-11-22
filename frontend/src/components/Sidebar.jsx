import { useState } from 'react';
import { Plus, RefreshCw } from 'lucide-react';
import { riskLevel } from '../lib/format';

function BrandMark() {
  // A shield with a scan line: static analysis of an app package
  return (
    <svg className="brand-mark" width="28" height="28" viewBox="0 0 28 28" aria-hidden="true">
      <path
        d="M14 2.5 4.5 6v7.2c0 6 4 10.6 9.5 12.3 5.5-1.7 9.5-6.3 9.5-12.3V6L14 2.5Z"
        fill="currentColor"
      />
      <path d="M8.5 13.5h11" stroke="var(--surface)" strokeWidth="2" strokeLinecap="round" />
      <path d="M10.5 17.5h7" stroke="var(--surface)" strokeWidth="2" strokeLinecap="round" opacity="0.6" />
    </svg>
  );
}

function relativeTime(value) {
  if (!value) return '';
  const minutes = Math.round((Date.now() - new Date(value)) / 60000);
  if (minutes < 1) return 'Just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} h ago`;
  return new Date(value).toLocaleDateString();
}

function ScanList({ tasks, activeId, onSelect, onRefresh }) {
  return (
    <section className="scans" aria-labelledby="scans-heading">
      <div className="scans-head">
        <h2 id="scans-heading">Your scans</h2>
        <button type="button" className="btn btn-icon" onClick={onRefresh} aria-label="Refresh scan list">
          <RefreshCw size={14} aria-hidden="true" />
        </button>
      </div>
      {tasks.length === 0 ? (
        <p className="hint">Scans you run appear here.</p>
      ) : (
        <ul className="scan-list">
          {tasks.map((task) => {
            const done = task.status === 'completed';
            const risk = riskLevel(task.malware_score, task.verdict);
            return (
              <li key={task.task_id}>
                <button
                  type="button"
                  className="scan-item"
                  aria-current={task.task_id === activeId ? 'true' : undefined}
                  onClick={() => onSelect(task.task_id)}
                >
                  <span className="scan-name" title={task.filename}>
                    {task.filename}
                    <span className="scan-time">{relativeTime(task.created_at)}</span>
                  </span>
                  <span
                    className={`score tone-${done ? risk.tone : 'muted'}`}
                    title={done ? `${risk.label}, ${task.malware_score.toFixed(1)}% malware probability` : undefined}
                  >
                    {done ? task.malware_score.toFixed(0) : task.status}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

function ApiKeyField({ apiKey, onChange }) {
  const [draft, setDraft] = useState(apiKey);

  return (
    <form
      className="settings"
      onSubmit={(e) => {
        e.preventDefault();
        onChange(draft.trim());
      }}
    >
      <label htmlFor="api-key">API key</label>
      <div className="inline-field">
        <input
          id="api-key"
          type="password"
          className="text-input"
          autoComplete="off"
          aria-describedby="api-key-hint"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
        />
        <button type="submit" className="btn">
          Save<span className="visually-hidden"> API key</span>
        </button>
      </div>
      <p id="api-key-hint" className="hint">
        {apiKey ? 'Saved for this browser session.' : 'Only needed if the server requires one.'}
      </p>
    </form>
  );
}

export default function Sidebar({ onNewScan, apiKey, onApiKeyChange, history, activeId, onSelectTask, onRefreshHistory }) {
  return (
    <aside className="sidebar">
      <div className="brand">
        <BrandMark />
        <div>
          <div className="brand-name">Nexus-Sec</div>
          <div className="brand-tagline">Android malware triage</div>
        </div>
      </div>

      <button type="button" className="btn btn-primary" onClick={onNewScan}>
        <Plus size={16} aria-hidden="true" /> New scan
      </button>

      <ScanList tasks={history} activeId={activeId} onSelect={onSelectTask} onRefresh={onRefreshHistory} />

      <ApiKeyField key={apiKey} apiKey={apiKey} onChange={onApiKeyChange} />
    </aside>
  );
}
