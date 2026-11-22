import { Check, Loader2 } from 'lucide-react';

const STEPS = [
  { key: 'uploaded', label: 'Upload and validate the APK' },
  { key: 'queued', label: 'Wait for an analysis worker' },
  { key: 'processing', label: 'Extract indicators, classify and explain' },
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
    <div className="progress">
      <h1>Scanning {filename}</h1>
      <p className="progress-lede">
        {phase === 'uploading'
          ? 'Uploading…'
          : 'Large APKs can take a few minutes. You can leave this page; the scan keeps running and appears under Your scans.'}
      </p>

      <ol className="steps" aria-live="polite">
        {STEPS.map((step, index) => {
          const state = index < active ? 'is-done' : index === active ? 'is-active' : '';
          return (
            <li key={step.key} className={`step ${state}`} aria-current={index === active ? 'step' : undefined}>
              <span className="step-dot" aria-hidden="true">
                {index < active ? (
                  <Check size={14} strokeWidth={3} />
                ) : index === active ? (
                  <Loader2 size={14} className="spin" />
                ) : (
                  index + 1
                )}
              </span>
              <span>{step.label}</span>
            </li>
          );
        })}
      </ol>

      {pollError && <p className="inline-warning">Connection problem: {pollError} Retrying…</p>}
    </div>
  );
}
