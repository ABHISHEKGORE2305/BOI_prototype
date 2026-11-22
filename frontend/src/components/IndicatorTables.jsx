import { CATEGORY_LABELS } from '../lib/format';
import { describeIndicator } from '../lib/indicators';

const LEVEL_BADGE = { high: 'badge-high', medium: 'badge-medium' };

export default function IndicatorTables({ features, shapData }) {
  const groups = Object.entries(features || {}).filter(([, list]) => list.length > 0);

  if (groups.length === 0) {
    return <p className="muted">No Drebin indicators were detected in this APK.</p>;
  }

  return (
    <div className="table-container animate-fade">
      {groups.map(([category, list]) => (
        <div className="table-section" key={category}>
          <h4>
            {CATEGORY_LABELS[category] || category} <span className="muted">({list.length})</span>
          </h4>
          <div className="table-scroll">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th scope="col">Indicator</th>
                  <th scope="col">Reference risk</th>
                  <th scope="col">SHAP</th>
                  <th scope="col">What it can be used for</th>
                </tr>
              </thead>
              <tbody>
                {list.map((feature) => {
                  const { level, description } = describeIndicator(feature);
                  const shap = shapData?.[feature];
                  return (
                    <tr key={feature}>
                      <td className="mono">{feature}</td>
                      <td>
                        {level ? (
                          <span className={`badge ${LEVEL_BADGE[level]}`}>{level}</span>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td className={`mono ${shap > 0 ? 'text-critical' : shap < 0 ? 'text-cyan' : 'muted'}`}>
                        {shap != null ? `${shap > 0 ? '+' : ''}${shap.toFixed(3)}` : '—'}
                      </td>
                      <td>{description || <span className="muted">—</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      ))}
    </div>
  );
}
