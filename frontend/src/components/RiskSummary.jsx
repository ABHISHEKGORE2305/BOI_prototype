import { countIndicators, formatDuration, riskLevel } from '../lib/format';

const TOTAL_FEATURES = 215;

function ProbabilityRuler({ score, threshold }) {
  const thresholdPct = threshold != null ? threshold * 100 : null;

  return (
    <div className="ruler" aria-hidden="true">
      <div className="ruler-track">
        {thresholdPct != null && (
          <>
            <div className="ruler-flagged" style={{ left: `${thresholdPct}%` }} />
            <div
              className={`ruler-threshold ${thresholdPct > 50 ? 'is-right' : ''}`}
              style={{ left: `${thresholdPct}%` }}
            >
              <span>Flagged above {thresholdPct.toFixed(1)}</span>
            </div>
          </>
        )}
        <div className="ruler-marker" style={{ left: `${score}%` }} />
      </div>
      <div className="ruler-scale">
        <span>0</span>
        <span>100</span>
      </div>
    </div>
  );
}

export default function RiskSummary({ task, threshold }) {
  const score = task.malware_score ?? 0;
  const risk = riskLevel(task.malware_score, task.verdict);
  const duration = formatDuration(task.created_at, task.completed_at);
  const indicatorCount = countIndicators(task.features);

  const thresholdText =
    threshold != null ? ` The model flags apps above ${(threshold * 100).toFixed(1)}.` : '';

  return (
    <section className={`verdict tone-${risk.tone}`} aria-labelledby="verdict-heading">
      <div className="verdict-top">
        <div className="verdict-call">
          <h2 id="verdict-heading" className="verdict-word">
            {task.verdict === 'malicious' ? 'Malicious' : 'Benign'}
          </h2>
          <span className="tag">{risk.label}</span>
        </div>
        <p className="verdict-probability">
          <span className="verdict-number">{score.toFixed(1)}%</span>
          <span>probability of malware</span>
        </p>
      </div>

      <ProbabilityRuler score={score} threshold={threshold} />
      <p className="visually-hidden">
        Malware probability {score.toFixed(1)} out of 100.{thresholdText}
      </p>

      <dl className="facts">
        <div>
          <dt>Indicators matched</dt>
          <dd>
            {indicatorCount} of {TOTAL_FEATURES}
          </dd>
        </div>
        <div>
          <dt>{task.cached_from ? 'Result' : 'Analysis time'}</dt>
          <dd>{task.cached_from ? 'Reused from an identical earlier scan' : duration || 'Unknown'}</dd>
        </div>
        <div>
          <dt>Model</dt>
          <dd className="code">{task.model_version || 'Unknown'}</dd>
        </div>
      </dl>
    </section>
  );
}
