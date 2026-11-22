import { useEffect, useState } from 'react';
import { getTask } from '../api';

// Classification is done but the LLM report may still be on its way
export const isAnalysisDone = (task) =>
  Boolean(task) && (task.status === 'completed' || task.status === 'failed');

export const isSettled = (task) =>
  isAnalysisDone(task) && (task.status === 'failed' || task.report_status !== 'pending');

const EMPTY = { task: null, error: null, gaveUp: false };

/**
 * Poll a task until its analysis and report are finished.
 *
 * Backs off from `initialDelay` to `maxDelay` and gives up after `giveUpAfter`
 * ms (a worker that is down shouldn't keep the tab polling forever).
 * Network errors are reported but polling continues; 401/404 stop it.
 */
export function useTaskPolling(
  taskId,
  apiKey,
  { initialDelay = 1000, maxDelay = 5000, giveUpAfter = 30 * 60 * 1000 } = {},
) {
  const [state, setState] = useState(EMPTY);

  useEffect(() => {
    setState(EMPTY);
    if (!taskId) return undefined;

    let cancelled = false;
    let timer;
    let delay = initialDelay;
    const startedAt = Date.now();

    const poll = async () => {
      try {
        const task = await getTask(taskId, apiKey);
        if (cancelled) return;
        setState((prev) => ({ ...prev, task, error: null }));
        if (isSettled(task)) return;
      } catch (err) {
        if (cancelled) return;
        setState((prev) => ({ ...prev, error: err.message }));
        if (err.status === 401 || err.status === 404) return;
      }

      if (Date.now() - startedAt > giveUpAfter) {
        setState((prev) => ({ ...prev, gaveUp: true }));
        return;
      }

      timer = setTimeout(poll, delay);
      delay = Math.min(delay * 1.5, maxDelay);
    };

    poll();

    return () => {
      cancelled = true;
      clearTimeout(timer);
    };
  }, [taskId, apiKey, initialDelay, maxDelay, giveUpAfter]);

  return state;
}
