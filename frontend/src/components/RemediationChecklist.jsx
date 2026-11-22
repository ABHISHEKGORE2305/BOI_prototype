import { useState } from 'react';
import { remediationSteps } from '../lib/remediation';

// Parent passes key={task_id} so the checklist resets for each scan
export default function RemediationChecklist({ task }) {
  const steps = remediationSteps(task);
  const [checked, setChecked] = useState(() => steps.map(() => false));

  const done = checked.filter(Boolean).length;
  const percent = steps.length ? Math.round((done / steps.length) * 100) : 0;

  return (
    <div className="remediation-container animate-fade">
      <p className="card-caption">
        Steps derived from the verdict and the indicators detected in this APK.
      </p>
      <div className="remediation-progress">
        <div
          className="progress-bar-container"
          role="progressbar"
          aria-valuenow={percent}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <div className={`progress-bar-fill ${percent === 100 ? 'complete' : ''}`} style={{ width: `${percent}%` }} />
        </div>
        <span className="progress-label">{percent}% complete</span>
      </div>

      <ul className="remediation-list">
        {steps.map((step, index) => (
          <li key={step}>
            <label className={`checklist-item ${checked[index] ? 'checked' : ''}`}>
              <input
                type="checkbox"
                checked={checked[index]}
                onChange={() =>
                  setChecked((prev) => prev.map((value, i) => (i === index ? !value : value)))
                }
              />
              <span>{step}</span>
            </label>
          </li>
        ))}
      </ul>
    </div>
  );
}
