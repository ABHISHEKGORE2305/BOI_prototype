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
    <section>
      <h3>Feature drift</h3>
      <p className="muted">
        Compares how often each indicator appears in recent scans with the training data. Large
        shifts mean the model is seeing apps unlike the ones it learned from.
      </p>
      <p className="drift-action">
        <button type="button" className="btn" onClick={load} disabled={loading}>
          <Activity size={16} aria-hidden="true" /> {loading ? 'Comparing…' : 'Compare recent scans'}
        </button>
      </p>
      {error && <p className="inline-warning">{error}</p>}
      {drift && drift.samples === 0 && <p className="muted">No completed scans to compare yet.</p>}
      {drift && drift.samples > 0 && (
        <>
          <p className="hint">
            Based on {drift.samples} distinct scans. Mean absolute shift {pct(drift.mean_abs_diff)}.
          </p>
          <div className="table-scroll">
            <table className="data-table">
              <thead>
                <tr>
                  <th scope="col">Indicator</th>
                  <th scope="col" className="num">Training</th>
                  <th scope="col" className="num">Recent scans</th>
                  <th scope="col" className="num">Shift</th>
                </tr>
              </thead>
              <tbody>
                {drift.features.map((row) => (
                  <tr key={row.feature}>
                    <td className="code">{row.feature}</td>
                    <td className="num">{pct(row.train)}</td>
                    <td className="num">{pct(row.live)}</td>
                    <td className="num">
                      {row.diff > 0 ? '+' : ''}
                      {pct(row.diff)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}

export default function ModelPanel({ model, modelError, apiKey }) {
  if (!model) {
    return <p className="muted">Model information is unavailable{modelError ? `: ${modelError}` : '.'}</p>;
  }

  const atThreshold = model.metrics.at_threshold || {};
  const maxImportance = model.global_importance[0]?.importance || 1;

  return (
    <div className="panel-stack">
      <dl className="info-grid">
        <dt>Version</dt>
        <dd className="code">{model.version}</dd>
        <dt>Trained</dt>
        <dd>{formatDateTime(model.trained_at)}</dd>
        <dt>Decision threshold</dt>
        <dd>
          {(model.threshold * 100).toFixed(1)}
          {model.max_fpr != null && (
            <span className="muted"> (tuned for at most {pct(model.max_fpr)} false positives)</span>
          )}
        </dd>
        <dt>Precision</dt>
        <dd>{pct(atThreshold.precision)} of flagged apps were malware</dd>
        <dt>Recall</dt>
        <dd>{pct(atThreshold.recall)} of malware was flagged</dd>
        <dt>False-positive rate</dt>
        <dd>{pct(atThreshold.false_positive_rate)} of benign apps were flagged</dd>
        <dt>ROC AUC</dt>
        <dd>{model.metrics.roc_auc}</dd>
      </dl>

      <p className="caution">
        Measured on a held-out part of the Drebin dataset, whose apps date from 2010–2012.
        Accuracy on modern malware is likely lower, so treat the verdict as one signal among
        several.
      </p>

      <section>
        <h3>Most influential indicators overall</h3>
        <p className="hint section-note">Mean absolute SHAP value across the test set.</p>
        <ol className="importance">
          {model.global_importance.slice(0, 10).map((row) => (
            <li key={row.feature}>
              <span className="code" title={row.feature}>{row.feature}</span>
              <span className="importance-bar" style={{ width: `${(row.importance / maxImportance) * 100}%` }} />
            </li>
          ))}
        </ol>
      </section>

      <DriftReport apiKey={apiKey} />
    </div>
  );
}
