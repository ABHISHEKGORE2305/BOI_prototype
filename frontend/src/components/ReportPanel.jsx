import { AlertTriangle, Info, Loader2 } from 'lucide-react';
import Markdown from 'react-markdown';
import remarkGfm from 'remark-gfm';

function ReportBody({ status, report }) {
  switch (status) {
    case 'completed':
      return (
        <div className="markdown">
          <Markdown remarkPlugins={[remarkGfm]}>{report}</Markdown>
        </div>
      );
    case 'pending':
      return (
        <p className="report-status">
          <Loader2 size={16} className="spin" aria-hidden="true" /> Writing the report. The verdict
          above is already final.
        </p>
      );
    case 'skipped':
      return (
        <p className="report-status">
          <Info size={16} aria-hidden="true" />
          <span>
            No report: this server has no Gemini API key configured. The verdict and indicators
            don&apos;t depend on it.
          </span>
        </p>
      );
    case 'failed':
      return (
        <p className="report-status">
          <AlertTriangle size={16} aria-hidden="true" />
          <span>
            The report could not be generated after several retries. The verdict and indicators
            above are unaffected.
          </span>
        </p>
      );
    default:
      return <p className="report-status">No report for this scan.</p>;
  }
}

export default function ReportPanel({ status, report }) {
  return (
    <section aria-labelledby="report-heading">
      <div className="section-head">
        <h2 id="report-heading">Analyst report</h2>
        <p>Drafted by an LLM from the indicators on this page. Check it before acting on it.</p>
      </div>
      <div className="report" aria-live="polite">
        <ReportBody status={status} report={report} />
      </div>
    </section>
  );
}
