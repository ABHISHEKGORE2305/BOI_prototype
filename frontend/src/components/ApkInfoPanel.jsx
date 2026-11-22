import { formatDateTime } from '../lib/format';

function Row({ label, children }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children ?? <span className="muted">—</span>}</dd>
    </>
  );
}

export default function ApkInfoPanel({ task }) {
  const info = task.apk_info;

  if (!info) {
    return <p className="muted">No APK metadata was recorded for this scan.</p>;
  }

  const counts = info.component_counts || {};

  return (
    <div className="table-container animate-fade">
      <dl className="info-grid">
        <Row label="Package"><span className="mono">{info.package}</span></Row>
        <Row label="App name">{info.app_name}</Row>
        <Row label="Version">
          {info.version_name} {info.version_code && <span className="muted">({info.version_code})</span>}
        </Row>
        <Row label="SDK">min {info.min_sdk ?? '?'} · target {info.target_sdk ?? '?'}</Row>
        <Row label="Debuggable">
          {info.debuggable ? <span className="badge badge-high">yes</span> : 'no'}
        </Row>
        <Row label="Signature schemes">{info.signature_schemes?.join(', ') || 'unsigned'}</Row>
        <Row label="Components">
          {counts.activities} activities · {counts.services} services · {counts.receivers} receivers ·{' '}
          {counts.providers} providers
        </Row>
        <Row label="DEX files">{info.dex_files}</Row>
        <Row label="SHA-256"><span className="mono break">{task.sha256}</span></Row>
        <Row label="Scanned">{formatDateTime(task.created_at)}</Row>
      </dl>

      <div className="table-section">
        <h4>Signing certificates</h4>
        {info.certificates?.length ? (
          <div className="table-scroll">
            <table className="cyber-table">
              <thead>
                <tr>
                  <th scope="col">Subject</th>
                  <th scope="col">Issuer</th>
                  <th scope="col">Expires</th>
                  <th scope="col">SHA-256</th>
                </tr>
              </thead>
              <tbody>
                {info.certificates.map((cert) => (
                  <tr key={cert.sha256}>
                    <td>{cert.subject}</td>
                    <td>{cert.issuer}</td>
                    <td>{formatDateTime(cert.not_after)}</td>
                    <td className="mono break">{cert.sha256}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="muted">No certificates found.</p>
        )}
      </div>

      <div className="table-section">
        <h4>Native libraries ({info.native_libraries?.length || 0})</h4>
        {info.native_libraries?.length ? (
          <ul className="mono-list">
            {info.native_libraries.map((lib) => <li key={lib}>{lib}</li>)}
          </ul>
        ) : (
          <p className="muted">None.</p>
        )}
      </div>

      <details className="table-section">
        <summary>All declared permissions ({info.permissions?.length || 0})</summary>
        <ul className="mono-list">
          {info.permissions?.map((perm) => <li key={perm}>{perm}</li>)}
        </ul>
      </details>
    </div>
  );
}
