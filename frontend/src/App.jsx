import { lazy, Suspense, useCallback, useEffect, useState } from 'react';
import { AlertTriangle, FlaskConical } from 'lucide-react';
import { getModelInfo, listTasks, uploadApk } from './api';
import PipelineProgress from './components/PipelineProgress';
import Sidebar from './components/Sidebar';
import Uploader from './components/Uploader';
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
    <div className="alert" role="alert">
      <AlertTriangle size={18} aria-hidden="true" />
      <div>
        <strong>{title}</strong>
        <p>{message}</p>
      </div>
    </div>
  );
}

function StartScreen({ onFile, onDemo, error }) {
  return (
    <div className="start">
      {error}
      <h1>Scan an Android app</h1>
      <p className="start-lede">
        Upload an APK to see how likely it is to be malware, which indicators drove that score, and
        what to do next. Nothing is installed or run; the app is only inspected.
      </p>
      <Uploader onFile={onFile} />
      <p className="start-alt">
        No APK to hand?{' '}
        <button type="button" className="btn btn-link" onClick={onDemo}>
          View a sample result
        </button>
      </p>
      <ol className="start-steps">
        <li>
          <strong>Static inspection</strong>
          Androguard reads the manifest, bytecode and strings.
        </li>
        <li>
          <strong>Calibrated verdict</strong>
          A LightGBM model scores 215 Drebin indicators.
        </li>
        <li>
          <strong>Explanation</strong>
          SHAP shows why, and an LLM drafts an analyst report.
        </li>
      </ol>
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
    window.scrollTo({ top: 0 });
    prefetchDashboard();
    setTaskId(id);
  };

  let content;
  if (demo) {
    content = (
      <>
        <div className="notice" role="status">
          <FlaskConical size={16} aria-hidden="true" />
          Sample data for illustration only. This is not the result of a real scan.
        </div>
        <Dashboard task={DEMO_TASK} model={model.info} modelError={model.error} apiKey={apiKey} exportable={false} />
      </>
    );
  } else if (uploadError) {
    content = (
      <StartScreen
        onFile={handleFile}
        onDemo={() => setDemo(true)}
        error={<ErrorBanner title={`Couldn't upload ${selectedName || 'the file'}`} message={uploadError} />}
      />
    );
  } else if (uploading) {
    content = <PipelineProgress phase="uploading" filename={selectedName} />;
  } else if (taskId && !task && pollError) {
    content = <ErrorBanner title="Couldn't load this scan" message={pollError} />;
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
        message="Stopped checking for results. Make sure the Celery worker is running; the scan will appear under Your scans when it finishes."
      />
    ) : (
      <PipelineProgress phase="tracking" task={task} filename={task?.filename || selectedName} pollError={pollError} />
    );
  } else if (task) {
    content = (
      <>
        {pollError && <p className="inline-warning">Connection problem while refreshing: {pollError}</p>}
        <Dashboard task={task} model={model.info} modelError={model.error} apiKey={apiKey} exportable />
      </>
    );
  } else {
    content = <StartScreen onFile={handleFile} onDemo={() => setDemo(true)} />;
  }

  return (
    <div className="app">
      <Sidebar
        onNewScan={reset}
        apiKey={apiKey}
        onApiKeyChange={handleApiKey}
        history={history}
        activeId={taskId}
        onSelectTask={selectTask}
        onRefreshHistory={refreshHistory}
      />

      <main className="workspace">
        <Suspense fallback={<p className="loading" role="status">Loading results…</p>}>
          {content}
        </Suspense>
      </main>
    </div>
  );
}
