import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { formatBytes, formatDateTime, formatDuration } from '../lib/format';
import { ErrorLine, Spinner } from './ui';

function statusStyle(status) {
  if (status === 'complete') return { color: '#39e569', borderColor: '#1a4224' };
  if (status === 'failed' || status === 'unavailable') return { color: '#f87171', borderColor: '#6b2525' };
  return { color: '#fbbf24', borderColor: '#785215' };
}

export default function NetworkEvidence({ investigation }) {
  const evidenceState = usePolling(
    () => api.getInvestigationEvidence(investigation.id),
    [investigation.id],
    5000,
    Boolean(investigation.id),
  );
  const items = evidenceState.data?.items || [];

  return (
    <section aria-labelledby="network-evidence-heading" style={{ marginTop: 16 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, marginBottom: 8 }}>
        <h3 id="network-evidence-heading" style={{ margin: 0, color: '#a3c4aa', fontSize: 12, fontWeight: 800, letterSpacing: '0.05em' }}>
          NETWORK EVIDENCE
        </h3>
        {evidenceState.refreshing && <span style={{ color: '#728c78', fontSize: 11 }}>Updating…</span>}
      </div>

      {evidenceState.error && <ErrorLine>{evidenceState.error}</ErrorLine>}
      {evidenceState.loading && !evidenceState.data ? (
        <div style={{ padding: 14, color: '#8b93a0', fontSize: 12 }}><Spinner /> Loading capture evidence…</div>
      ) : items.length === 0 ? (
        <div style={{ padding: 12, background: 'rgba(6, 12, 8, 0.5)', border: '1px solid #142e1a', borderRadius: 6, color: '#8b93a0', fontSize: 12 }}>
          No PCAP artifacts are attached to this investigation.
        </div>
      ) : (
        <div style={{ overflowX: 'auto', border: '1px solid #1d3524', borderRadius: 6 }}>
          <table style={{ width: '100%', minWidth: 700, borderCollapse: 'collapse', textAlign: 'left', fontSize: 11.5 }}>
            <caption style={{ position: 'absolute', width: 1, height: 1, padding: 0, margin: -1, overflow: 'hidden', clip: 'rect(0, 0, 0, 0)', whiteSpace: 'nowrap', border: 0 }}>
              Packet capture files attached to investigation {investigation.id}
            </caption>
            <thead>
              <tr style={{ color: '#8b93a0', borderBottom: '1px solid #1d3524' }}>
                {['Filename', 'Stored size', 'Capture duration', 'Captured at', 'Status', 'Download'].map((label) => (
                  <th key={label} scope="col" style={{ padding: '9px 10px', fontWeight: 700 }}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((item) => {
                const tone = statusStyle(item.status);
                return (
                  <tr key={item.file_id} style={{ borderBottom: '1px solid #14231a', color: '#d8dee9' }}>
                    <td style={{ padding: '10px', maxWidth: 260, overflowWrap: 'anywhere', fontFamily: 'JetBrains Mono, monospace' }}>
                      {item.filename || (item.status === 'unavailable' ? 'Capture unavailable' : 'Capture file pending')}
                      {item.error_message && <div style={{ marginTop: 4, color: '#8b93a0', fontFamily: 'inherit' }}>{item.error_message}</div>}
                    </td>
                    <td style={{ padding: '10px', whiteSpace: 'nowrap' }}>
                      {item.size_bytes == null ? '—' : formatBytes(item.size_bytes)}
                    </td>
                    <td style={{ padding: '10px', whiteSpace: 'nowrap' }}>
                      {item.duration_seconds == null ? '—' : formatDuration(item.duration_seconds * 1000)}
                    </td>
                    <td style={{ padding: '10px', whiteSpace: 'nowrap' }}>
                      {formatDateTime(item.capture_started_at || item.captured_at)}
                    </td>
                    <td style={{ padding: '10px' }}>
                      <span style={{ ...tone, display: 'inline-block', border: '1px solid', borderRadius: 4, padding: '3px 6px', textTransform: 'uppercase', fontSize: 10, fontWeight: 700 }}>
                        {item.status}
                      </span>
                    </td>
                    <td style={{ padding: '10px' }}>
                      {item.status === 'complete' ? (
                        <a
                          href={api.investigationEvidenceDownloadUrl(investigation.id, item.file_id)}
                          aria-label={`Download ${item.filename || `PCAP evidence ${item.file_id}`}`}
                          style={{ display: 'inline-flex', alignItems: 'center', minHeight: 36, padding: '6px 10px', border: '1px solid #355a3c', borderRadius: 4, background: '#17251a', color: '#c6ff00', fontSize: 11, fontWeight: 700, textDecoration: 'none' }}
                        >
                          Download
                        </a>
                      ) : (
                        <button
                          type="button"
                          disabled
                          aria-label={`Download ${item.filename || `PCAP evidence ${item.file_id}`}`}
                          style={{ minHeight: 36, padding: '6px 10px', border: '1px solid #262b32', borderRadius: 4, background: '#101512', color: '#656c77', cursor: 'not-allowed', fontSize: 11, fontWeight: 700 }}
                        >
                          Download
                        </button>
                      )}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
