import { useState } from 'react';
import ApkInfoPanel from './ApkInfoPanel';
import IndicatorTables from './IndicatorTables';
import ModelPanel from './ModelPanel';
import RemediationChecklist from './RemediationChecklist';
import ReportPanel from './ReportPanel';
import RiskSummary from './RiskSummary';
import ShapChart from './ShapChart';

const TABS = [
  { id: 'indicators', label: 'Detected indicators' },
  { id: 'apk', label: 'APK metadata' },
  { id: 'remediation', label: 'Remediation' },
  { id: 'model', label: 'Model & drift' },
];

export default function Dashboard({ task, model, modelError, apiKey }) {
  const [activeTab, setActiveTab] = useState('indicators');

  return (
    <>
      <RiskSummary task={task} threshold={model?.version === task.model_version ? model.threshold : null} />

      <section className="mid-row animate-fade">
        <ShapChart shapData={task.shap_data} features={task.features} />
        <ReportPanel status={task.report_status} report={task.llm_report} />
      </section>

      <section className="nexus-card animate-fade">
        <div className="tabs-header" role="tablist">
          {TABS.map((tab) => (
            <button
              key={tab.id}
              type="button"
              role="tab"
              id={`tab-${tab.id}`}
              aria-selected={activeTab === tab.id}
              aria-controls={`panel-${tab.id}`}
              className={`tab-btn ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              {tab.label}
            </button>
          ))}
        </div>

        <div className="tab-content" role="tabpanel" id={`panel-${activeTab}`} aria-labelledby={`tab-${activeTab}`}>
          {activeTab === 'indicators' && (
            <IndicatorTables features={task.features} shapData={task.shap_data} />
          )}
          {activeTab === 'apk' && <ApkInfoPanel task={task} />}
          {activeTab === 'remediation' && <RemediationChecklist key={task.task_id} task={task} />}
          {activeTab === 'model' && <ModelPanel model={model} modelError={modelError} apiKey={apiKey} />}
        </div>
      </section>
    </>
  );
}
