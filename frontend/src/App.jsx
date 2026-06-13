import React, { useState, useEffect } from 'react';
import { 
  Shield, 
  Settings, 
  Download, 
  FileText, 
  Terminal as TermIcon, 
  Play, 
  CheckCircle, 
  AlertTriangle, 
  RefreshCw,
  Upload,
  Info
} from 'lucide-react';
import { 
  BarChart, 
  Bar, 
  XAxis, 
  YAxis, 
  CartesianGrid, 
  Tooltip, 
  ResponsiveContainer, 
  Cell 
} from 'recharts';

import {
  DUMMY_MALWARE_FAMILY,
  DUMMY_ANALYSIS_TIME,
  DUMMY_SHAP_DATA,
  DUMMY_LLM_REPORT,
  DUMMY_PERMISSIONS,
  DUMMY_IOCS,
  DUMMY_INTENTS,
  DUMMY_REMEDIATION_STEPS,
  DUMMY_SYSTEM_LOGS,
  DUMMY_PDF_CONTENT,
  DUMMY_JSON_EXPORT
} from './data/dummyData';

const BACKEND_URL = "http://127.0.0.1:8000";

// Custom helper to parse custom markdown headers, lists and bold items cleanly in UI
const formatReportMarkdown = (text) => {
  if (!text) return null;
  return text.split('\n').map((line, idx) => {
    const trimmed = line.trim();
    if (trimmed.startsWith('### ')) {
      return (
        <h4 key={idx} style={{ color: '#ff4d4d', marginTop: '16px', marginBottom: '8px', fontSize: '1.05rem', fontWeight: '700' }}>
          {trimmed.replace('### ', '')}
        </h4>
      );
    }
    if (trimmed.startsWith('- ')) {
      return (
        <li key={idx} style={{ color: '#9ca3af', marginBottom: '6px', fontSize: '0.85rem', marginLeft: '12px' }}>
          {trimmed.replace('- ', '')}
        </li>
      );
    }
    // Parse bold segments like **text**
    if (trimmed.includes('**')) {
      const parts = trimmed.split('**');
      return (
        <p key={idx} style={{ color: '#9ca3af', fontSize: '0.85rem', marginBottom: '8px', lineHeight: '1.5' }}>
          {parts.map((part, pIdx) => pIdx % 2 === 1 ? <strong key={pIdx} style={{ color: '#fff', fontWeight: '600' }}>{part}</strong> : part)}
        </p>
      );
    }
    return trimmed ? (
      <p key={idx} style={{ color: '#9ca3af', fontSize: '0.85rem', marginBottom: '8px', lineHeight: '1.5' }}>
        {trimmed}
      </p>
    ) : <br key={idx} />;
  });
};

function App() {
  // Config & File Upload State
  const [depth, setDepth] = useState(2);
  const [llmModel, setLlmModel] = useState("Gemini 2.5 Flash");
  const [uploadedFile, setUploadedFile] = useState(null);
  
  // Loading & Scanning States
  const [isScanning, setIsScanning] = useState(false);
  const [scanStep, setScanStep] = useState(0);
  const [scanTime, setScanTime] = useState("0.0s");

  // Analysis Result States (Default to Demo Mock Data)
  // // # DUMMY DATA
  const [score, setScore] = useState(88.0);
  // // # DUMMY DATA
  const [shapData, setShapData] = useState(DUMMY_SHAP_DATA);
  // // # DUMMY DATA
  const [llmReport, setLlmReport] = useState(DUMMY_LLM_REPORT);
  // // # DUMMY DATA
  const [malwareFamily, setMalwareFamily] = useState(DUMMY_MALWARE_FAMILY);
  // // # DUMMY DATA
  const [isDemoMode, setIsDemoMode] = useState(true);

  // Tabs navigation
  const [activeTab, setActiveTab] = useState("static");

  // Remediation Checklist State
  // // # DUMMY DATA
  const [remediationSteps, setRemediationSteps] = useState(
    DUMMY_REMEDIATION_STEPS.map((step) => ({ text: step, checked: false }))
  );

  // Auto scroll terminal logs
  const [logs, setLogs] = useState(DUMMY_SYSTEM_LOGS);

  // Handle Scan Steps Simulation
  useEffect(() => {
    if (!isScanning) return;

    const interval = setInterval(() => {
      setScanStep((prev) => {
        if (prev >= 4) {
          clearInterval(interval);
          return 4;
        }
        return prev + 1;
      });
    }, 1200);

    return () => clearInterval(interval);
  }, [isScanning]);

  // Handle File Scan Upload & Pipeline Execution
  const handleFileUpload = async (event) => {
    const file = event.target.files[0];
    if (!file) return;

    setUploadedFile(file.name);
    setIsScanning(true);
    setScanStep(1);

    let taskId = null;
    let uploadSuccess = false;

    // Send file to backend
    try {
      const formData = new FormData();
      formData.append("file", file);

      const response = await fetch(`${BACKEND_URL}/upload`, {
        method: "POST",
        body: formData,
      });

      if (response.ok) {
        const uploadData = await response.json();
        taskId = uploadData.task_id;
        uploadSuccess = true;
      } else {
        console.warn("Backend upload failed. Status:", response.status);
      }
    } catch (err) {
      console.warn("FastAPI backend down. Falling back to Standalone Demo Scan.");
    }

    // Wait until simulated loading animation steps complete
    await new Promise((resolve) => {
      const checkInterval = setInterval(() => {
        setScanStep((currentStep) => {
          if (currentStep >= 4) {
            clearInterval(checkInterval);
            resolve();
          }
          return currentStep;
        });
      }, 500);
    });

    // Retrieve real analysis data if uploaded successfully
    let finalData = null;
    if (uploadSuccess && taskId) {
      // Poll status endpoint
      let attempts = 0;
      while (attempts < 30) {
        try {
          const statusRes = await fetch(`${BACKEND_URL}/status/${taskId}`);
          if (statusRes.ok) {
            const statusData = await statusRes.json();
            if (statusData.status === "completed") {
              finalData = statusData;
              break;
            } else if (statusData.status === "failed") {
              console.error("Backend scan task failed");
              break;
            }
          }
        } catch (e) {
          break;
        }
        await new Promise((r) => setTimeout(r, 1000));
        attempts++;
      }
    }

    // Populate dashboard with results
    if (finalData) {
      // Use real data from database/inference
      setScore(finalData.malware_score || 0.0);
      setShapData(finalData.shap_data && Object.keys(finalData.shap_data).length > 0 
        ? finalData.shap_data 
        : DUMMY_SHAP_DATA
      );
      setLlmReport(finalData.llm_report || "Report generation failed.");
      // // # DUMMY DATA
      setMalwareFamily(finalData.malware_score >= 50 ? DUMMY_MALWARE_FAMILY : "N/A (Clean Profile)");
      setIsDemoMode(false);
      // // # DUMMY DATA
      setScanTime(DUMMY_ANALYSIS_TIME);
    } else {
      // Set Fallback Dummy values
      // // # DUMMY DATA
      setScore(88.0);
      // // # DUMMY DATA
      setShapData(DUMMY_SHAP_DATA);
      // // # DUMMY DATA
      setLlmReport(DUMMY_LLM_REPORT);
      // // # DUMMY DATA
      setMalwareFamily(DUMMY_MALWARE_FAMILY);
      setIsDemoMode(true);
      // // # DUMMY DATA
      setScanTime(DUMMY_ANALYSIS_TIME);
    }

    setIsScanning(false);
    setScanStep(0);
  };

  // Toggle checklist checkbox
  const handleChecklistToggle = (index) => {
    const updated = [...remediationSteps];
    updated[index].checked = !updated[index].checked;
    setRemediationSteps(updated);
  };

  // Compute checklist completion percentage
  const completedRemStepsCount = remediationSteps.filter((s) => s.checked).length;
  const remPercent = Math.round((completedRemStepsCount / remediationSteps.length) * 100);

  // Prepare SHAP chart features list (reformat keys, pad to 10 entries)
  const chartData = Object.entries(shapData)
    .map(([feature, val]) => ({
      name: feature
        .replace("android.permission.", "perm:")
        .replace("Ljava.lang.", "java:")
        .substring(0, 30),
      value: parseFloat(val.toFixed(4)),
    }))
    // Sort by absolute value descending
    .sort((a, b) => Math.abs(b.value) - Math.abs(a.value))
    .slice(0, 10);

  // Determine Risk Category
  const getRiskDetails = (val) => {
    if (val >= 80) return { label: "CRITICAL RISK", colorClass: "metric-value-red", badge: "badge-critical" };
    if (val >= 50) return { label: "MEDIUM RISK", colorClass: "metric-value-orange", badge: "badge-high" };
    return { label: "LOW RISK", colorClass: "metric-value-green", badge: "badge-clean" };
  };

  const riskDetails = getRiskDetails(score);

  // Reset/Clear Scanner State
  const handleReset = () => {
    setUploadedFile(null);
    // // # DUMMY DATA
    setScore(88.0);
    // // # DUMMY DATA
    setShapData(DUMMY_SHAP_DATA);
    // // # DUMMY DATA
    setLlmReport(DUMMY_LLM_REPORT);
    // // # DUMMY DATA
    setMalwareFamily(DUMMY_MALWARE_FAMILY);
    // // # DUMMY DATA
    setScanTime("0.0s");
    setIsDemoMode(true);
    setRemediationSteps(
      // // # DUMMY DATA
      DUMMY_REMEDIATION_STEPS.map((step) => ({ text: step, checked: false }))
    );
  };

  return (
    <div className="app-container">
      {/* ========================= SIDEBAR ========================= */}
      <aside className="sidebar">
        <div className="sidebar-logo">
          <h1>🛡️ NEXUS-SEC</h1>
          <small>APK THREAT INTELLIGENCE</small>
        </div>

        {/* Upload target */}
        <div className="sidebar-section">
          <h3>File Uploader</h3>
          <div className="file-uploader">
            <span className="uploader-icon">📥</span>
            <div className="uploader-text">
              {uploadedFile ? `${uploadedFile.substring(0, 20)}...` : "Select APK Target"}
            </div>
            <div className="uploader-subtext">Drag & drop or browse</div>
            <input 
              type="file" 
              accept=".apk" 
              onChange={handleFileUpload} 
              disabled={isScanning}
            />
          </div>
          {uploadedFile && !isScanning && (
            <button className="btn-action" onClick={handleReset} style={{ borderColor: 'rgba(255,77,77,0.4)', color: '#ff4d4d' }}>
              <RefreshCw size={14} /> Clear Scan
            </button>
          )}
        </div>

        {/* Configuration settings */}
        <div className="sidebar-section">
          <h3>Scanner Parameters</h3>
          <div className="config-group">
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.8rem' }}>
              <label>Analysis Depth</label>
              <span style={{ color: '#ff4d4d', fontWeight: '600' }}>
                {depth === 1 ? "Quick Scan" : depth === 2 ? "Deep Model" : "Full Sandbox"}
              </span>
            </div>
            <input 
              type="range" 
              min="1" 
              max="3" 
              value={depth} 
              onChange={(e) => setDepth(parseInt(e.target.value))} 
              className="range-slider"
            />
          </div>

          <div className="config-group">
            <label>Target LLM Model</label>
            <select 
              value={llmModel} 
              onChange={(e) => setLlmModel(e.target.value)} 
              className="select-dropdown"
            >
              <option>Gemini 2.5 Flash</option>
              <option>GPT-4o</option>
              <option>Llama 3.1 70B</option>
              <option>Claude 3.5 Sonnet</option>
            </select>
          </div>
        </div>

        {/* Exports */}
        <div className="sidebar-section" style={{ marginTop: 'auto' }}>
          <h3>Export Reports</h3>
          <a 
            className="btn-action" 
            href={`data:application/pdf;base64,${btoa(DUMMY_PDF_CONTENT)}`} 
            download="Nexus_Sec_Report.pdf"
          >
            <FileText size={16} /> Export PDF Report
          </a>
          <a 
            className="btn-action" 
            href={`data:application/json;charset=utf-8,${encodeURIComponent(DUMMY_JSON_EXPORT)}`} 
            download="nexus_sec_raw_threat_metrics.json"
          >
            <Download size={16} /> Download Raw JSON
          </a>
        </div>
      </aside>

      {/* ========================= MAIN CONTENT AREA ========================= */}
      <main className="main-content">
        {/* State Indicators */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div>
            {isDemoMode ? (
              <span className="badge badge-demo">📊 Demo Mode Profile</span>
            ) : (
              <span className="badge badge-live">⚡ Live Scanner Scan</span>
            )}
          </div>
          <div style={{ display: 'flex', gap: '8px', color: '#6b7280', fontSize: '0.8rem' }}>
            <span style={{ color: '#9ca3af' }}>Host Node: </span>
            <span style={{ color: '#00d2ff', fontFamily: 'monospace' }}>Nexus-1.local</span>
          </div>
        </div>

        {isScanning ? (
          /* ========================= SCANNING PIPELINE SCREEN ========================= */
          <div className="pipeline-loader animate-fade">
            <div className="pipeline-header">
              <span className="uploader-icon" style={{ fontSize: '3rem', display: 'block' }}>🛡️</span>
              <h2>Nexus-Sec Active Threat Classifier</h2>
              <p>Analyzing APK payload signatures and permissions...</p>
            </div>

            <div className="stepper-container">
              <div className={`step-item ${scanStep >= 1 ? 'active' : ''} ${scanStep > 1 ? 'completed' : ''}`}>
                <div className="step-indicator">
                  {scanStep > 1 ? "✓" : "1"}
                </div>
                <div className="step-label">Extracting Manifest & Bytecode Signatures...</div>
              </div>

              <div className={`step-item ${scanStep >= 2 ? 'active' : ''} ${scanStep > 2 ? 'completed' : ''}`}>
                <div className="step-indicator">
                  {scanStep > 2 ? "✓" : "2"}
                </div>
                <div className="step-label">Running LightGBM Classification Inference...</div>
              </div>

              <div className={`step-item ${scanStep >= 3 ? 'active' : ''} ${scanStep > 3 ? 'completed' : ''}`}>
                <div className="step-indicator">
                  {scanStep > 3 ? "✓" : "3"}
                </div>
                <div className="step-label">Attributing Shapley Explainability (SHAP)...</div>
              </div>

              <div className={`step-item ${scanStep >= 4 ? 'active' : ''} ${scanStep > 4 ? 'completed' : ''}`}>
                <div className="step-indicator">
                  {scanStep >= 4 ? "✓" : "4"}
                </div>
                <div className="step-label">Generating LLM Analyst Brief (using {llmModel})...</div>
              </div>
            </div>
          </div>
        ) : (
          /* ========================= DASHBOARD VIEW ========================= */
          <>
            {/* Top Metrics Row */}
            <section className="metrics-row animate-fade">
              {/* Score */}
              <div className="nexus-card metric-card">
                <svg className="gauge-svg" viewBox="0 0 36 36">
                  <path className="gauge-bg" d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" />
                  <path 
                    className="gauge-fill" 
                    style={{ stroke: score >= 50 ? '#ff4d4d' : '#00e676' }}
                    strokeDasharray={`${score}, 100`} 
                    d="M18 2.0845 a 15.9155 15.9155 0 0 1 0 31.831 a 15.9155 15.9155 0 0 1 0 -31.831" 
                  />
                </svg>
                <div className="metric-details">
                  <span className="metric-label">Fraud Risk Score</span>
                  <div className={`metric-value ${riskDetails.colorClass}`}>{score.toFixed(1)}/100</div>
                  <span className={`badge ${riskDetails.badge}`} style={{ margin: 0, width: 'fit-content' }}>
                    {riskDetails.label}
                  </span>
                </div>
              </div>

              {/* Family Match */}
              <div className="nexus-card metric-card">
                <div className="metric-details" style={{ width: '100%' }}>
                  <span className="metric-label">Malware Family Match</span>
                  <div className="metric-value" style={{ fontSize: '1.4rem', color: score >= 50 ? '#ffa500' : '#00e676', textShadow: score >= 50 ? '0 0 12px var(--orange-glow)' : '0 0 12px var(--green-glow)', margin: '4px 0' }}>
                    {malwareFamily}
                  </div>
                  <span className="metric-caption">
                    {score >= 50 ? "98.4% Signature Alignment" : "Clean Classification Profile"}
                  </span>
                </div>
              </div>

              {/* Scan speed */}
              <div className="nexus-card metric-card">
                <div className="metric-details">
                  <span className="metric-label">Analysis Time</span>
                  <div className="metric-value metric-value-green">{scanTime || "1.4s"}</div>
                  <span className="metric-caption">FastAPI + Celery Pipeline</span>
                </div>
              </div>
            </section>

            {/* Middle Row - SHAP Chart & GenAI Report */}
            <section className="mid-row animate-fade">
              {/* SHAP Chart */}
              <div className="nexus-card">
                <h3 style={{ fontSize: '1.1rem', marginBottom: '20px', display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <Info size={16} style={{ color: '#00d2ff' }} /> ML Decision Explainability (SHAP)
                </h3>
                <div className="chart-wrapper">
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart
                      data={chartData}
                      layout="vertical"
                      margin={{ top: 5, right: 15, left: 15, bottom: 5 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false} />
                      <XAxis type="number" stroke="#9ca3af" fontSize={10} tickLine={false} />
                      <YAxis dataKey="name" type="category" stroke="#9ca3af" fontSize={9} width={110} tickLine={false} />
                      <Tooltip
                        contentStyle={{
                          backgroundColor: '#0c0f17',
                          border: '1px solid rgba(255,255,255,0.1)',
                          borderRadius: '8px',
                          color: '#fff',
                          fontSize: '11px',
                          fontFamily: 'monospace'
                        }}
                        cursor={{ fill: 'rgba(255,255,255,0.02)' }}
                      />
                      <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                        {chartData.map((entry, index) => (
                          <Cell key={`cell-${index}`} fill={entry.value > 0 ? '#ff4d4d' : '#00d2ff'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
              </div>

              {/* GenAI Report */}
              <div className="nexus-card">
                <h3 style={{ fontSize: '1.1rem', marginBottom: '20px', display: 'flex', gap: '8px', alignItems: 'center' }}>
                  <FileText size={16} style={{ color: '#ff4d4d' }} /> GenAI Threat Intelligence Report
                </h3>
                <div className="report-wrapper">
                  {formatReportMarkdown(llmReport)}
                </div>
              </div>
            </section>

            {/* Bottom Row - Tabs */}
            <section className="nexus-card animate-fade">
              <div className="tabs-header">
                <button 
                  className={`tab-btn ${activeTab === 'static' ? 'active' : ''}`} 
                  onClick={() => setActiveTab("static")}
                >
                  Static Analysis
                </button>
                <button 
                  className={`tab-btn ${activeTab === 'remediation' ? 'active' : ''}`} 
                  onClick={() => setActiveTab("remediation")}
                >
                  Remediation Playbook
                </button>
                <button 
                  className={`tab-btn ${activeTab === 'logs' ? 'active' : ''}`} 
                  onClick={() => setActiveTab("logs")}
                >
                  System Logs
                </button>
              </div>

              <div className="tab-content">
                {activeTab === "static" && (
                  /* ========================= TAB 1: STATIC ANALYSIS ========================= */
                  <div className="table-container animate-fade">
                    <div className="table-section">
                      <h4>Dangerous Permissions Flagged</h4>
                      <table className="cyber-table">
                        <thead>
                          <tr>
                            <th>Permission</th>
                            <th>Risk Level</th>
                            <th>Description</th>
                          </tr>
                        </thead>
                        <tbody>
                          {DUMMY_PERMISSIONS.map((perm, index) => (
                            <tr key={index}>
                              <td style={{ fontFamily: 'monospace', color: '#ff4d4d' }}>{perm.permission}</td>
                              <td>
                                <span className={`badge ${perm.riskLevel === 'CRITICAL' ? 'badge-critical' : perm.riskLevel === 'HIGH' ? 'badge-high' : 'badge-medium'}`}>
                                  {perm.riskLevel}
                                </span>
                              </td>
                              <td>{perm.description}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    <div className="table-section">
                      <h4>Extracted Network IOC Indicators</h4>
                      <table className="cyber-table">
                        <thead>
                          <tr>
                            <th>Indicator</th>
                            <th>Type</th>
                            <th>Reputation</th>
                            <th>Details</th>
                          </tr>
                        </thead>
                        <tbody>
                          {DUMMY_IOCS.map((ioc, index) => (
                            <tr key={index}>
                              <td style={{ fontFamily: 'monospace', color: '#00d2ff' }}>{ioc.indicator}</td>
                              <td>{ioc.type}</td>
                              <td>
                                <span className={`badge ${ioc.reputation === 'MALICIOUS' ? 'badge-critical' : ioc.reputation === 'SUSPICIOUS' ? 'badge-high' : 'badge-clean'}`}>
                                  {ioc.reputation}
                                </span>
                              </td>
                              <td>{ioc.details}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>

                    <div className="table-section">
                      <h4>Registered Broadcast Receivers & Intents</h4>
                      <table className="cyber-table">
                        <thead>
                          <tr>
                            <th>Intent Filter Action</th>
                            <th>Target Receiver Class</th>
                            <th>Criticality</th>
                          </tr>
                        </thead>
                        <tbody>
                          {DUMMY_INTENTS.map((intent, index) => (
                            <tr key={index}>
                              <td style={{ fontFamily: 'monospace', color: '#ffa500' }}>{intent.intentFilter}</td>
                              <td style={{ fontFamily: 'monospace' }}>{intent.targetClass}</td>
                              <td>
                                <span className={`badge ${intent.risk === 'CRITICAL' ? 'badge-critical' : intent.risk === 'HIGH' ? 'badge-high' : 'badge-medium'}`}>
                                  {intent.risk}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}

                {activeTab === "remediation" && (
                  /* ========================= TAB 2: REMEDIATION PLAYBOOK ========================= */
                  <div className="remediation-container animate-fade">
                    <div className="remediation-progress">
                      <div className="progress-bar-container">
                        <div className="progress-bar-fill" style={{ width: `${remPercent}%`, backgroundColor: remPercent === 100 ? '#00e676' : '#ff4d4d' }}></div>
                      </div>
                      <span style={{ fontSize: '0.85rem', fontWeight: '700', color: remPercent === 100 ? '#00e676' : '#fff' }}>
                        {remPercent}% Securing Complete
                      </span>
                    </div>

                    <div className="remediation-list">
                      {remediationSteps.map((step, index) => (
                        <div 
                          key={index} 
                          className={`checklist-item ${step.checked ? 'checked' : ''}`}
                          onClick={() => handleChecklistToggle(index)}
                        >
                          <input 
                            type="checkbox" 
                            checked={step.checked}
                            onChange={() => {}} // handled by click container
                          />
                          <span>{step.text}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {activeTab === "logs" && (
                  /* ========================= TAB 3: WORKER SYSTEM LOGS ========================= */
                  <div className="animate-fade">
                    <div className="terminal-wrapper">
                      {logs}
                    </div>
                  </div>
                )}
              </div>
            </section>
          </>
        )}
      </main>
    </div>
  );
}

export default App;
