import { useState } from 'react';
import { Download, FileText, KeyRound, RefreshCw, Shield } from 'lucide-react';
import Uploader from './Uploader';
import { riskLevel } from '../lib/format';

function downloadJson(task) {
  const blob = new Blob([JSON.stringify(task, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `nexus-sec-${(task.filename || task.task_id).replace(/\.apk$/i, '')}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function ApiKeyField({ apiKey, onChange }) {
  const [draft, setDraft] = useState(apiKey);

  return (
    <form
      className="config-group"
      onSubmit={(e) => {
        e.preventDefault();
        onChange(draft.trim());
      }}
    >
      <label htmlFor="api-key">API key (if the server requires one)</label>
      <div className="inline-field">
        <input
          id="api-key"
          type="password"
          className="text-input"
          autoComplete="off"
          value={draft}
          onChange={(e) => setDraft(e.target.value)}
          placeholder="Not set"
        />
        <button type="submit" className="btn-small" aria-label="Save API key">
          <KeyRound size={14} aria-hidden="true" />
        </button>
      </div>
    </form>
  );
}

function History({ tasks, activeId, onSelect, onRefresh }) {
  return (
    <div className="sidebar-section">
      <h3 className="section-title-row">
        Recent scans
        <button type="button" className="icon-btn" onClick={onRefresh} aria-label="Refresh scan history">
          <RefreshCw size={12} aria-hidden="true" />
        </button>
      </h3>
      {tasks.length === 0 ? (
        <p className="muted small">No scans yet.</p>
      ) : (
        <ul className="history-list">
          {tasks.map((task) => {
            const risk = riskLevel(task.malware_score, task.verdict);
            return (
              <li key={task.task_id}>
                <button
                  type="button"
                  className={`history-item ${task.task_id === activeId ? 'active' : ''}`}
                  onClick={() => onSelect(task.task_id)}
                >
                  <span className="history-name">{task.filename}</span>
                  <span className={`badge badge-${task.status === 'completed' ? risk.tone : 'muted'}`}>
                    {task.status === 'completed' ? `${task.malware_score?.toFixed(0)}` : task.status}
                  </span>
                </button>
              </li>
            );
          })}
        </ul>
      )}
    </div>
  );
}

export default function Sidebar({
  onFile,
  uploading,
  selectedName,
  apiKey,
  onApiKeyChange,
  history,
  activeId,
  onSelectTask,
  onRefreshHistory,
  exportableTask,
}) {
  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <h1>
          <Shield size={22} aria-hidden="true" /> NEXUS-SEC
        </h1>
        <small>APK threat intelligence</small>
      </div>

      <div className="sidebar-section">
        <h3>Analyse APK</h3>
        <Uploader onFile={onFile} disabled={uploading} selectedName={selectedName} />
      </div>

      <div className="sidebar-section">
        <h3>Connection</h3>
        <ApiKeyField key={apiKey} apiKey={apiKey} onChange={onApiKeyChange} />
      </div>

      <History
        tasks={history}
        activeId={activeId}
        onSelect={onSelectTask}
        onRefresh={onRefreshHistory}
      />

      <div className="sidebar-section sidebar-exports">
        <h3>Export report</h3>
        <button
          type="button"
          className="btn-action"
          disabled={!exportableTask}
          onClick={() => window.print()}
        >
          <FileText size={16} aria-hidden="true" /> Print / save as PDF
        </button>
        <button
          type="button"
          className="btn-action"
          disabled={!exportableTask}
          onClick={() => downloadJson(exportableTask)}
        >
          <Download size={16} aria-hidden="true" /> Download raw JSON
        </button>
      </div>
    </aside>
  );
}
