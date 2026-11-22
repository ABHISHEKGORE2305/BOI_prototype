import { useState } from 'react';
import { Check, Copy, Download, Printer } from 'lucide-react';
import ApkInfoPanel from './ApkInfoPanel';
import IndicatorTables from './IndicatorTables';
import ModelPanel from './ModelPanel';
import RemediationChecklist from './RemediationChecklist';
import ReportPanel from './ReportPanel';
import RiskSummary from './RiskSummary';
import ShapChart from './ShapChart';
import { countIndicators } from '../lib/format';

function downloadJson(task) {
  const blob = new Blob([JSON.stringify(task, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `nexus-sec-${(task.filename || task.task_id).replace(/\.apk$/i, '')}.json`;
  link.click();
  URL.revokeObjectURL(url);
}

function CopyableHash({ value }) {
  const [copied, setCopied] = useState(false);
  if (!value) return <span className="muted">Unknown</span>;

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard blocked; the full hash is in the App details tab
    }
  };

  return (
    <>
      <span className="code" title={value}>
        {value.slice(0, 12)}…{value.slice(-6)}
      </span>
      <button type="button" className="btn btn-icon" onClick={copy} aria-label="Copy SHA-256">
        {copied ? <Check size={14} aria-hidden="true" /> : <Copy size={14} aria-hidden="true" />}
      </button>
    </>
  );
}

export default function Dashboard({ task, model, modelError, apiKey, exportable }) {
  const [activeTab, setActiveTab] = useState('indicators');

  const tabs = [
    { id: 'indicators', label: 'Indicators', count: countIndicators(task.features) },
    { id: 'app', label: 'App details' },
    { id: 'response', label: 'Response checklist' },
    { id: 'model', label: 'Model' },
  ];

  return (
    <article className="sheet">
      <header className="sheet-head">
        <div>
          <h1>{task.filename}</h1>
          <dl className="identity">
            <div>
              <dt>Package</dt>
              <dd className="code">{task.apk_info?.package || 'Unknown'}</dd>
            </div>
            <div>
              <dt>SHA-256</dt>
              <dd>
                <CopyableHash value={task.sha256} />
              </dd>
            </div>
          </dl>
        </div>
        {exportable && (
          <div className="sheet-actions">
            <button type="button" className="btn" onClick={() => downloadJson(task)}>
              <Download size={16} aria-hidden="true" /> Download JSON
            </button>
            <button type="button" className="btn" onClick={() => window.print()}>
              <Printer size={16} aria-hidden="true" /> Print report
            </button>
          </div>
        )}
      </header>

      <RiskSummary
        task={task}
        threshold={model?.version === task.model_version ? model.threshold : null}
      />

      <div className="split">
        <ShapChart shapData={task.shap_data} features={task.features} />
        <ReportPanel status={task.report_status} report={task.llm_report} />
      </div>

      <div className="details">
        <div className="tabs" role="tablist" aria-label="Scan details">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              id={`tab-${tab.id}`}
              aria-selected={activeTab === tab.id}
              aria-controls={`panel-${tab.id}`}
              className="tab"
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
              {tab.count != null && <span className="tab-count">{tab.count}</span>}
            </button>
          ))}
        </div>

        <div
          className="tab-panel"
          role="tabpanel"
          id={`panel-${activeTab}`}
          aria-labelledby={`tab-${activeTab}`}
        >
          {activeTab === 'indicators' && (
            <IndicatorTables features={task.features} shapData={task.shap_data} />
          )}
          {activeTab === 'app' && <ApkInfoPanel task={task} />}
          {activeTab === 'response' && <RemediationChecklist key={task.task_id} task={task} />}
          {activeTab === 'model' && <ModelPanel model={model} modelError={modelError} apiKey={apiKey} />}
        </div>
      </div>
    </article>
  );
}
