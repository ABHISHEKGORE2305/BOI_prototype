import { countIndicators, formatDuration, riskLevel } from '../lib/format';

const GAUGE_PATH =
  'M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831';

export default function RiskSummary({ task, threshold }) {
  const score = task.malware_score ?? 0;
  const risk = riskLevel(task.malware_score, task.verdict);
  const duration = formatDuration(task.created_at, task.completed_at);
  const indicatorCount = countIndicators(task.features);

  return (
    <section className="metrics-row animate-fade" aria-label="Scan summary">
      <div className="nexus-card metric-card">
        <svg className="gauge-svg" viewBox="0 0 36 36" role="img" aria-label={`Risk score ${score.toFixed(1)} of 100`}>
          <path className="gauge-bg" d={GAUGE_PATH} />
          <path className={`gauge-fill tone-${risk.tone}`} strokeDasharray={`${score}, 100`} d={GAUGE_PATH} />
        </svg>
        <div className="metric-details">
          <span className="metric-label">Malware probability</span>
          <div className={`metric-value text-${risk.tone}`}>{score.toFixed(1)}/100</div>
          <span className={`badge badge-${risk.tone}`}>{risk.label}</span>
        </div>
      </div>

      <div className="nexus-card metric-card">
        <div className="metric-details">
          <span className="metric-label">Classifier verdict</span>
          <div className={`metric-value metric-value-text text-${risk.tone}`}>
            {task.verdict === 'malicious' ? 'Malicious' : 'Benign'}
          </div>
          <span className="metric-caption">
            {threshold != null
              ? `Decision threshold ${(threshold * 100).toFixed(1)} · model ${task.model_version}`
              : `Model ${task.model_version || 'unknown'}`}
          </span>
        </div>
      </div>

      <div className="nexus-card metric-card">
        <div className="metric-details">
          <span className="metric-label">Indicators matched</span>
          <div className="metric-value text-cyan">{indicatorCount}<span className="metric-unit">/215</span></div>
          <span className="metric-caption">
            {task.cached_from
              ? 'Reused result of an identical earlier scan'
              : duration
                ? `Analysed in ${duration}`
                : 'Drebin static feature set'}
          </span>
        </div>
      </div>
    </section>
  );
}
