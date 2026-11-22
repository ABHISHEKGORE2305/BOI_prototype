import { useState } from 'react';
import { remediationSteps } from '../lib/remediation';

// Parent passes key={task_id} so the checklist resets for each scan
export default function RemediationChecklist({ task }) {
  const steps = remediationSteps(task);
  const [checked, setChecked] = useState(() => steps.map(() => false));

  const done = checked.filter(Boolean).length;
  const percent = steps.length ? Math.round((done / steps.length) * 100) : 0;

  return (
    <div>
      <p className="muted">Suggested next steps for this verdict and the indicators found.</p>
      <div className="checklist-progress">
        <div
          className="meter"
          role="progressbar"
          aria-label="Checklist progress"
          aria-valuenow={percent}
          aria-valuemin={0}
          aria-valuemax={100}
        >
          <div className={`meter-fill ${percent === 100 ? 'is-complete' : ''}`} style={{ width: `${percent}%` }} />
        </div>
        <span>
          {done} of {steps.length} done
        </span>
      </div>

      <ul className="checklist">
        {steps.map((step, index) => (
          <li key={step}>
            <label className={checked[index] ? 'is-checked' : ''}>
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
