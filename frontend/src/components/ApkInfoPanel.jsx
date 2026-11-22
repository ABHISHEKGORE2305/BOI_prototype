import { formatDateTime } from '../lib/format';

function Row({ label, children }) {
  return (
    <>
      <dt>{label}</dt>
      <dd>{children ?? <span className="muted">—</span>}</dd>
    </>
  );
}

function plural(count = 0, singular, pluralForm = `${singular}s`) {
  return `${count} ${count === 1 ? singular : pluralForm}`;
}

export default function ApkInfoPanel({ task }) {
  const info = task.apk_info;

  if (!info) {
    return <p className="muted">No app details were recorded for this scan.</p>;
  }

  const counts = info.component_counts || {};

  return (
    <div className="panel-stack">
      <dl className="info-grid">
        <Row label="Package"><span className="code">{info.package}</span></Row>
        <Row label="App name">{info.app_name}</Row>
        <Row label="Version">
          {info.version_name} {info.version_code && <span className="muted">(code {info.version_code})</span>}
        </Row>
        <Row label="Android SDK">
          Minimum {info.min_sdk ?? 'not set'}, target {info.target_sdk ?? 'not set'}
        </Row>
        <Row label="Debuggable">
          {info.debuggable ? <span className="tag tone-high">Yes</span> : 'No'}
        </Row>
        <Row label="Signature schemes">
          {info.signature_schemes?.length ? info.signature_schemes.join(', ') : 'Unsigned'}
        </Row>
        <Row label="Components">
          {[
            plural(counts.activities, 'activity', 'activities'),
            plural(counts.services, 'service'),
            plural(counts.receivers, 'receiver'),
            plural(counts.providers, 'provider'),
          ].join(', ')}
        </Row>
        <Row label="DEX files">{info.dex_files}</Row>
        <Row label="SHA-256"><span className="code">{task.sha256}</span></Row>
        <Row label="Scanned">{formatDateTime(task.created_at)}</Row>
      </dl>

      <section>
        <h3>Signing certificates</h3>
        {info.certificates?.length ? (
          <div className="table-scroll">
            <table className="data-table">
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
                    <td className="code">{cert.sha256}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p className="muted">No signing certificates found.</p>
        )}
      </section>

      <section>
        <h3>
          Native libraries <span className="muted">{info.native_libraries?.length || 0}</span>
        </h3>
        {info.native_libraries?.length ? (
          <ul className="code-list code">
            {info.native_libraries.map((lib) => <li key={lib}>{lib}</li>)}
          </ul>
        ) : (
          <p className="muted">None.</p>
        )}
      </section>

      <details>
        <summary>
          All declared permissions <span className="muted">{info.permissions?.length || 0}</span>
        </summary>
        <ul className="code-list code">
          {info.permissions?.map((perm) => <li key={perm}>{perm}</li>)}
        </ul>
      </details>
    </div>
  );
}
