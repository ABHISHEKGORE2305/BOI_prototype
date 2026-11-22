import { useState } from 'react';
import { Activity } from 'lucide-react';
import { getDrift } from '../api';
import { formatDateTime } from '../lib/format';

const pct = (value) => (value == null ? '—' : `${(value * 100).toFixed(1)}%`);

function DriftReport({ apiKey }) {
  const [state, setState] = useState({ loading: false, drift: null, error: null });

  const load = async () => {
    setState({ loading: true, drift: null, error: null });
    try {
      setState({ loading: false, drift: await getDrift(apiKey), error: null });
    } catch (err) {
      setState({ loading: false, drift: null, error: err.message });
    }
  };

  const { loading, drift, error } = state;

  return (
    <div className="table-section">
      <h4>Feature drift</h4>
      <p className="card-caption">
        Compares how often each indicator appears in recent scans with the training data. Large
        shifts mean the model is seeing apps unlike those it learned from.
      </p>
      <button type="button" className="btn-small btn-wide" onClick={load} disabled={loading}>
        <Activity size={14} aria-hidden="true" /> {loading ? 'Computing…' : 'Compute drift'}
      </button>
      {error && <p className="warning-text">{error}</p>}
      {drift && drift.samples === 0 && <p className="muted">No completed scans yet.</p>}
      {drift && drift.samples > 0 && (
        <>
          <p className="muted small">
            {drift.samples} distinct scans · mean absolute shift {pct(drift.mean_abs_diff)}
          </p>
          <div className="table-scroll">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th scope="col">Indicator</th>
                  <th scope="col">Training</th>
                  <th scope="col">Recent scans</th>
                  <th scope="col">Shift</th>
                </tr>
              </thead>
              <tbody>
                {drift.features.map((row) => (
                  <tr key={row.feature}>
                    <td className="mono">{row.feature}</td>
                    <td>{pct(row.train)}</td>
                    <td>{pct(row.live)}</td>
                    <td className={row.diff > 0 ? 'text-high' : 'text-cyan'}>
                      {row.diff > 0 ? '+' : ''}{pct(row.diff)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </div>
  );
}

export default function ModelPanel({ model, modelError, apiKey }) {
  if (!model) {
    return <p className="muted">Model information unavailable{modelError ? `: ${modelError}` : '.'}</p>;
  }

  const atThreshold = model.metrics.at_threshold || {};

  return (
    <div className="table-container animate-fade">
      <dl className="info-grid">
        <dt>Version</dt>
        <dd className="mono">{model.version}</dd>
        <dt>Trained</dt>
        <dd>{formatDateTime(model.trained_at)}</dd>
        <dt>Decision threshold</dt>
        <dd>
          {(model.threshold * 100).toFixed(1)}
          {model.max_fpr != null && (
            <span className="muted"> (tuned for ≤ {pct(model.max_fpr)} false positives)</span>
          )}
        </dd>
        <dt>Held-out test set</dt>
        <dd>
          precision {pct(atThreshold.precision)} · recall {pct(atThreshold.recall)} · false-positive
          rate {pct(atThreshold.false_positive_rate)} · ROC AUC {model.metrics.roc_auc}
        </dd>
      </dl>

      <p className="warning-text">
        Trained on the Drebin dataset (apps from 2010–2012). Accuracy on modern malware is likely
        lower than these figures; treat the verdict as one signal among several.
      </p>

      <div className="table-section">
        <h4>Most influential indicators overall (mean |SHAP|)</h4>
        <ol className="importance-list">
          {model.global_importance.slice(0, 10).map((row) => {
            const max = model.global_importance[0].importance || 1;
            return (
              <li key={row.feature}>
                <span className="mono">{row.feature}</span>
                <span className="importance-bar" style={{ width: `${(row.importance / max) * 100}%` }} />
              </li>
            );
          })}
        </ol>
      </div>

      <DriftReport apiKey={apiKey} />
    </div>
  );
}
