import { Loader2 } from 'lucide-react';

const STEPS = [
  { key: 'uploaded', label: 'APK received and validated' },
  { key: 'queued', label: 'Waiting for an analysis worker' },
  { key: 'processing', label: 'Static extraction, classification and SHAP attribution' },
  { key: 'completed', label: 'Results ready' },
];

function currentStep(phase, task) {
  if (phase === 'uploading') return 0;
  if (!task || task.status === 'queued') return 1;
  if (task.status === 'processing') return 2;
  return 3;
}

export default function PipelineProgress({ phase, task, filename, pollError }) {
  const active = currentStep(phase, task);

  return (
    <div className="pipeline-loader animate-fade">
      <div className="pipeline-header">
        <Loader2 size={40} className="spin accent-red" aria-hidden="true" />
        <h2>Analysing {filename}</h2>
        <p>
          {phase === 'uploading'
            ? 'Uploading…'
            : 'Large APKs can take a few minutes. You can leave this page; the scan keeps running.'}
        </p>
      </div>

      <ol className="stepper-container" aria-live="polite">
        {STEPS.map((step, index) => {
          const state = index < active ? 'completed' : index === active ? 'active' : '';
          return (
            <li key={step.key} className={`step-item ${state}`}>
              <span className="step-indicator">{index < active ? '✓' : index + 1}</span>
              <span className="step-label">{step.label}</span>
            </li>
          );
        })}
      </ol>

      {pollError && <p className="warning-text">Connection problem: {pollError} Retrying…</p>}
    </div>
  );
}
