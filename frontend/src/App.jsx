import { lazy, Suspense, useCallback, useEffect, useState } from 'react';
import { AlertTriangle, FlaskConical, X } from 'lucide-react';
import { getModelInfo, listTasks, uploadApk } from './api';
import PipelineProgress from './components/PipelineProgress';
import Sidebar from './components/Sidebar';
import { DEMO_TASK } from './data/demoResult';
import { isAnalysisDone, useTaskPolling } from './hooks/useTaskPolling';
import { validateApk } from './lib/validate';

const API_KEY_STORAGE = 'nexus-sec-api-key';

// The dashboard pulls in Recharts and the Markdown renderer (most of the
// bundle). Load it only once there is a result to show, and start fetching
// it as soon as a scan begins so it's usually ready by the time it's needed.
const loadDashboard = () => import('./components/Dashboard');
const Dashboard = lazy(loadDashboard);

function prefetchDashboard() {
  loadDashboard().catch(() => {
    // Only a warm-up; a real failure surfaces when the dashboard renders
  });
}

function readStoredKey() {
  try {
    return sessionStorage.getItem(API_KEY_STORAGE) || '';
  } catch {
    return '';
  }
}

function storeKey(key) {
  try {
    if (key) sessionStorage.setItem(API_KEY_STORAGE, key);
    else sessionStorage.removeItem(API_KEY_STORAGE);
  } catch {
    // Storage unavailable (private mode); the key lives in memory only
  }
}

function ErrorBanner({ title, message }) {
  return (
    <div className="nexus-card error-banner animate-fade" role="alert">
      <AlertTriangle size={20} aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        <p>{message}</p>
      </div>
    </div>
  );
}

function EmptyState({ onDemo }) {
  return (
    <div className="empty-state animate-fade">
      <h2>Upload an APK to begin</h2>
      <p>
        Nexus-Sec extracts static indicators with Androguard, scores them with a calibrated LightGBM
        model, explains the decision with SHAP and drafts an analyst report.
      </p>
      <button type="button" className="btn-action btn-inline" onClick={onDemo}>
        <FlaskConical size={16} aria-hidden="true" /> View a sample result
      </button>
    </div>
  );
}

export default function App({ pollOptions }) {
  const [apiKey, setApiKey] = useState(readStoredKey);
  const [taskId, setTaskId] = useState(null);
  const [demo, setDemo] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [selectedName, setSelectedName] = useState(null);
  const [uploadError, setUploadError] = useState(null);
  const [history, setHistory] = useState([]);
  const [model, setModel] = useState({ info: null, error: null });

  const { task, error: pollError, gaveUp } = useTaskPolling(taskId, apiKey, pollOptions);

  const refreshHistory = useCallback(async () => {
    try {
      setHistory(await listTasks(apiKey));
    } catch {
      // History is a convenience; errors surface through the main flow
    }
  }, [apiKey]);

  useEffect(() => {
    refreshHistory();
    getModelInfo(apiKey)
      .then((info) => setModel({ info, error: null }))
      .catch((err) => setModel({ info: null, error: err.message }));
  }, [apiKey, refreshHistory]);

  // Update the sidebar once a scan finishes
  const analysisDone = isAnalysisDone(task);
  useEffect(() => {
    if (analysisDone) refreshHistory();
  }, [analysisDone, refreshHistory]);

  const handleApiKey = (key) => {
    storeKey(key);
    setApiKey(key);
  };

  const reset = () => {
    setTaskId(null);
    setDemo(false);
    setUploadError(null);
    setSelectedName(null);
  };

  const handleFile = async (file) => {
    reset();
    setSelectedName(file.name);
    prefetchDashboard();

    const problem = validateApk(file);
    if (problem) {
      setUploadError(problem);
      return;
    }

    setUploading(true);
    try {
      const { task_id: newTaskId } = await uploadApk(file, apiKey);
      setTaskId(newTaskId);
      refreshHistory();
    } catch (err) {
      setUploadError(err.message);
    } finally {
      setUploading(false);
    }
  };

  const selectTask = (id) => {
    reset();
    prefetchDashboard();
    setTaskId(id);
  };

  let content;
  if (demo) {
    content = (
      <>
        <div className="demo-banner" role="status">
          <FlaskConical size={16} aria-hidden="true" />
          Sample data for illustration only — this is not the result of a real scan.
        </div>
        <Dashboard task={DEMO_TASK} model={model.info} modelError={model.error} apiKey={apiKey} />
      </>
    );
  } else if (uploadError) {
    content = <ErrorBanner title="Upload failed" message={uploadError} />;
  } else if (uploading) {
    content = <PipelineProgress phase="uploading" filename={selectedName} />;
  } else if (taskId && !task && pollError) {
    content = <ErrorBanner title="Could not load scan" message={pollError} />;
  } else if (task?.status === 'failed') {
    content = (
      <ErrorBanner
        title={`Analysis of ${task.filename} failed`}
        message={task.error || 'The worker reported an error without details.'}
      />
    );
  } else if (taskId && !analysisDone) {
    content = gaveUp ? (
      <ErrorBanner
        title="Still waiting for the analysis worker"
        message="Stopped polling. Check that the Celery worker is running; the scan will appear under Recent scans when it finishes."
      />
    ) : (
      <PipelineProgress phase="tracking" task={task} filename={task?.filename || selectedName} pollError={pollError} />
    );
  } else if (task) {
    content = (
      <>
        {pollError && <p className="warning-text">Connection problem while refreshing: {pollError}</p>}
        <Dashboard task={task} model={model.info} modelError={model.error} apiKey={apiKey} />
      </>
    );
  } else {
    content = <EmptyState onDemo={() => setDemo(true)} />;
  }

  const showingResult = demo || Boolean(task) || Boolean(uploadError);

  return (
    <div className="app-container">
      <Sidebar
        onFile={handleFile}
        uploading={uploading}
        selectedName={selectedName}
        apiKey={apiKey}
        onApiKeyChange={handleApiKey}
        history={history}
        activeId={taskId}
        onSelectTask={selectTask}
        onRefreshHistory={refreshHistory}
        exportableTask={!demo && task?.status === 'completed' ? task : null}
      />

      <main className="main-content">
        <div className="main-header">
          <div>
            {demo && <span className="badge badge-demo">Demo sample</span>}
            {!demo && task?.status === 'completed' && (
              <span className="badge badge-live">
                {task.filename}
                {task.cached_from ? ' · cached result' : ''}
              </span>
            )}
          </div>
          {showingResult && (
            <button type="button" className="btn-small" onClick={reset}>
              <X size={14} aria-hidden="true" /> Clear
            </button>
          )}
        </div>

        <Suspense
          fallback={
            <p className="nexus-card loading-text" role="status">
              Loading results…
            </p>
          }
        >
          {content}
        </Suspense>
      </main>
    </div>
  );
}
