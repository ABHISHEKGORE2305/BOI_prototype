import { CATEGORY_LABELS } from '../lib/format';
import { describeIndicator } from '../lib/indicators';

const LEVEL_TONE = { high: 'high', medium: 'medium' };
const LEVEL_LABEL = { high: 'High', medium: 'Medium' };

export default function IndicatorTables({ features, shapData }) {
  const groups = Object.entries(features || {}).filter(([, list]) => list.length > 0);

  if (groups.length === 0) {
    return <p className="muted">None of the 215 Drebin indicators were found in this APK.</p>;
  }

  return (
    <div className="panel-stack">
      {groups.map(([category, list]) => (
        <section key={category}>
          <h3>
            {CATEGORY_LABELS[category] || category} <span className="muted">{list.length}</span>
          </h3>
          <div className="table-scroll">
            <table className="data-table is-fixed">
              <colgroup>
                <col style={{ width: '34%' }} />
                <col style={{ width: '13%' }} />
                <col style={{ width: '10%' }} />
                <col />
              </colgroup>
              <thead>
                <tr>
                  <th scope="col">Indicator</th>
                  <th scope="col">Typical risk</th>
                  <th scope="col" className="num">SHAP</th>
                  <th scope="col">What it allows</th>
                </tr>
              </thead>
              <tbody>
                {list.map((feature) => {
                  const { level, description } = describeIndicator(feature);
                  const shap = shapData?.[feature];
                  const direction = shap > 0 ? 'towards-malware' : shap < 0 ? 'towards-benign' : 'muted';
                  return (
                    <tr key={feature}>
                      <td className="code">{feature}</td>
                      <td>
                        {level ? (
                          <span className={`tag tone-${LEVEL_TONE[level]}`}>{LEVEL_LABEL[level]}</span>
                        ) : (
                          <span className="muted">—</span>
                        )}
                      </td>
                      <td className={`num ${direction}`}>
                        {shap != null ? `${shap > 0 ? '+' : ''}${shap.toFixed(3)}` : '—'}
                      </td>
                      <td>{description || <span className="muted">—</span>}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>
      ))}
    </div>
  );
}
