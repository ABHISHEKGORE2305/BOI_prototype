import { shortFeatureName } from '../lib/format';

const TOP_N = 10;

function formatValue(value) {
  return `${value > 0 ? '+' : value < 0 ? '−' : ''}${Math.abs(value).toFixed(2)}`;
}

export default function ShapChart({ shapData, features }) {
  const present = new Set(Object.values(features || {}).flat());

  const rows = Object.entries(shapData || {})
    .map(([feature, value]) => ({ feature, value, present: present.has(feature) }))
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, TOP_N);

  const max = Math.max(...rows.map((row) => Math.abs(row.value)), 1e-9);

  return (
    <section aria-labelledby="why-heading">
      <div className="section-head">
        <h2 id="why-heading">Why the model decided this</h2>
        <p>
          The indicators that moved the score most (SHAP values), pushing it towards benign or
          malware. An indicator can also count by being absent from the app.
        </p>
      </div>

      {rows.length === 0 ? (
        <p className="muted">No attribution data for this scan.</p>
      ) : (
        <>
          <div className="shap-row shap-legend" aria-hidden="true">
            <span />
            <span className="shap-legend-track">
              <span>← Benign</span>
              <span>Malware →</span>
            </span>
            <span />
          </div>
          <ol className="shap-list">
            {rows.map((row) => {
              const width = `${(Math.abs(row.value) / max) * 50}%`;
              const direction = row.value >= 0 ? 'malware' : 'benign';
              return (
                <li key={row.feature} className="shap-row">
                  <span className="shap-name">
                    <span className="code" title={row.feature}>
                      {shortFeatureName(row.feature, 40)}
                    </span>
                    <span className="shap-presence">{row.present ? 'Present' : 'Absent'}</span>
                  </span>
                  <span className="shap-track" aria-hidden="true">
                    <span className={`shap-bar is-${direction}`} style={{ width }} />
                  </span>
                  <span className={`shap-value towards-${direction}`}>
                    {formatValue(row.value)}
                    <span className="visually-hidden"> towards {direction}</span>
                  </span>
                </li>
              );
            })}
          </ol>
        </>
      )}
    </section>
  );
}
