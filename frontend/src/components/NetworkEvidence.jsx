import { useState } from 'react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { formatBytes, formatDateTime, formatDuration, formatNumber } from '../lib/format';
import { CAN_WRITE } from '../lib/role';
import { ErrorLine, Spinner } from './ui';
import InvestigationAnalysis from './InvestigationAnalysis';

function statusStyle(status) {
  if (status === 'complete') return { color: '#39e569', borderColor: '#1a4224' };
  if (status === 'failed' || status === 'unavailable' || status === 'rolled_back') {
    return { color: '#f87171', borderColor: '#6b2525' };
  }
  if (status === 'not_started') return { color: '#9aa39c', borderColor: '#39413b' };
  return { color: '#fbbf24', borderColor: '#785215' };
}

function Status({ value }) {
  const style = statusStyle(value);
  return <span style={{ ...style, display: 'inline-block', border: '1px solid', borderRadius: 4, padding: '3px 6px', textTransform: 'uppercase', fontSize: 10, fontWeight: 700, whiteSpace: 'nowrap' }}>{value?.replaceAll('_', ' ') || 'unknown'}</span>;
}

export default function NetworkEvidence({ investigation, refreshMs, showAnalysis = false }) {
  const [busyAction, setBusyAction] = useState('');
  const [retrying, setRetrying] = useState(() => new Set());
  const [actionMessage, setActionMessage] = useState('');
  const [actionError, setActionError] = useState('');
  const evidenceState = usePolling(
    () => api.getInvestigationEvidence(investigation.id),
    [investigation.id],
    refreshMs,
    Boolean(investigation.id),
  );
  const captureState = usePolling(
    () => api.getNodeCaptureStatus(investigation.node_id),
    [investigation.node_id],
    10000,
    Boolean(investigation.node_id),
  );
  const items = evidenceState.data?.items || [];
  const capture = captureState.data;

  async function runCaptureAction(action) {
    setBusyAction(action);
    setActionMessage('');
    setActionError('');
    try {
      if (action === 'start') {
        await api.startNodeCapture(investigation.node_id);
        setActionMessage('Packet capture started.');
        captureState.refresh();
      } else if (action === 'stop') {
        await api.stopNodeCapture(investigation.node_id);
        setActionMessage('Packet capture stopped.');
        captureState.refresh();
      } else {
        const result = await api.captureInvestigationEvidence(investigation.id);
        setActionMessage(result.queued_files ? `Snapshot queued for ${result.queued_files} file${result.queued_files === 1 ? '' : 's'}.` : 'No capture files were available. Check the capture status or try again later.');
        evidenceState.refresh();
      }
    } catch (error) {
      setActionError(error.message || 'Capture action failed.');
    } finally {
      setBusyAction('');
    }
  }

  async function retryTransfer(fileId) {
    setRetrying((current) => new Set(current).add(fileId));
    setActionMessage('');
    setActionError('');
    try {
      await api.retryInvestigationEvidenceTransfer(investigation.id, fileId);
      setActionMessage(`Transfer for evidence #${fileId} queued again.`);
      evidenceState.refresh();
    } catch (error) {
      setActionError(error.message || 'Transfer retry failed.');
    } finally {
      setRetrying((current) => {
        const next = new Set(current);
        next.delete(fileId);
        return next;
      });
    }
  }

  const collectorState = captureState.error
    ? 'unavailable'
    : !capture
      ? 'checking'
      : capture.running
        ? 'running'
          : capture.configured_enabled
            ? 'stopped'
            : 'stopped (manual start)';

  return (
    <section aria-labelledby="network-evidence-heading" style={{ marginTop: 12 }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 12, marginBottom: 10, flexWrap: 'wrap' }}>
        <div>
          <h3 id="network-evidence-heading" style={{ margin: 0, color: '#d7e3d9', fontSize: 14, fontWeight: 750 }}>
            Network evidence
          </h3>
          <p style={{ margin: '4px 0 0', color: '#8b93a0', fontSize: 11 }}>Capture, transfer, and analysis status for investigation #{investigation.id}.</p>
        </div>
        {evidenceState.refreshing && <span style={{ color: '#8b93a0', fontSize: 11 }}>Updating evidence…</span>}
      </div>

      <div style={{ border: '1px solid #26332a', background: '#101512', borderRadius: 5, padding: '12px 14px', marginBottom: 14 }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12, flexWrap: 'wrap' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span aria-hidden="true" style={{ width: 8, height: 8, borderRadius: '50%', background: capture?.running ? '#39e569' : captureState.error ? '#f87171' : '#fbbf24' }} />
            <strong style={{ color: '#e5e9e6', fontSize: 12 }}>Collector capture: {collectorState}</strong>
            {capture?.interface && <span style={{ color: '#9aa39c', font: '11px JetBrains Mono, monospace' }}>{capture.interface}</span>}
          </div>
          {CAN_WRITE && (
            <div style={{ display: 'flex', gap: 7, flexWrap: 'wrap' }}>
              {capture?.running ? (
                <>
                  <button type="button" className="btn sm" onClick={() => runCaptureAction('snapshot')} disabled={Boolean(busyAction)} style={{ minHeight: 36 }}>
                    {busyAction === 'snapshot' ? 'Queuing snapshot…' : 'Capture snapshot'}
                  </button>
                  <button type="button" className="btn sm" onClick={() => runCaptureAction('stop')} disabled={Boolean(busyAction)} style={{ minHeight: 36 }}>
                    {busyAction === 'stop' ? 'Stopping…' : 'Stop capture'}
                  </button>
                </>
              ) : (
                <button type="button" className="btn sm" onClick={() => runCaptureAction('start')} disabled={!capture || Boolean(captureState.error) || Boolean(busyAction)} style={{ minHeight: 36 }}>
                  {busyAction === 'start' ? 'Starting…' : 'Start capture'}
                </button>
              )}
            </div>
          )}
        </div>
        {captureState.loading && !capture && <div style={{ marginTop: 9, color: '#8b93a0', fontSize: 11 }}><Spinner /> Checking collector availability…</div>}
        {capture && !captureState.error && (
          <div style={{ display: 'flex', gap: '8px 22px', flexWrap: 'wrap', marginTop: 10, color: '#aab3ac', fontSize: 11 }}>
            <span>Snap length: {capture.snaplen == null ? '—' : `${formatNumber(capture.snaplen, 0)} bytes`}</span>
            <span>Retained: {capture.retained_bytes == null ? '—' : formatBytes(capture.retained_bytes)}</span>
            <span>Files: {capture.file_count == null ? '—' : formatNumber(capture.file_count, 0)}</span>
            <span>Coverage: {capture.coverage_seconds == null ? '—' : formatDuration(capture.coverage_seconds * 1000)}</span>
          </div>
        )}
        {captureState.error && <div role="status" style={{ marginTop: 8, color: '#fca5a5', fontSize: 11 }}>Collector status is unavailable: {captureState.error}</div>}
        {capture?.last_error && <div role="status" style={{ marginTop: 8, color: '#fbbf24', fontSize: 11 }}>{capture.last_error}</div>}
        {actionMessage && <div role="status" style={{ marginTop: 8, color: '#a3c4aa', fontSize: 11 }}>{actionMessage}</div>}
        {actionError && <div role="alert" style={{ marginTop: 8, color: '#fca5a5', fontSize: 11 }}>{actionError}</div>}
      </div>

      {evidenceState.error && <ErrorLine>{evidenceState.error}</ErrorLine>}
      {evidenceState.loading && !evidenceState.data ? (
        <div style={{ padding: 14, color: '#8b93a0', fontSize: 12 }}><Spinner /> Loading capture evidence…</div>
      ) : items.length === 0 ? (
        <div style={{ padding: 12, background: 'rgba(6, 12, 8, 0.5)', border: '1px solid #26332a', borderRadius: 5, color: '#aab3ac', fontSize: 12 }}>
          No capture evidence is attached yet. Start capture on the collector, then capture a snapshot for this investigation.
        </div>
      ) : (
        <div style={{ overflowX: 'auto', border: '1px solid #26332a', borderRadius: 5 }}>
          <table style={{ width: '100%', minWidth: 820, borderCollapse: 'collapse', textAlign: 'left', fontSize: 11.5 }}>
            <caption style={{ position: 'absolute', width: 1, height: 1, padding: 0, margin: -1, overflow: 'hidden', clip: 'rect(0, 0, 0, 0)', whiteSpace: 'nowrap', border: 0 }}>
              Packet capture files attached to investigation {investigation.id}
            </caption>
            <thead>
              <tr style={{ color: '#8b93a0', borderBottom: '1px solid #26332a' }}>
                {['Capture', 'Stored size', 'Duration', 'Captured', 'Transfer', 'Analysis', 'Action'].map((label) => (
                  <th key={label} scope="col" style={{ padding: '9px 10px', fontWeight: 700 }}>{label}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {items.map((item) => (
                <tr key={item.file_id} style={{ borderBottom: '1px solid #1c2820', color: '#d8dee9', verticalAlign: 'top' }}>
                  <td style={{ padding: '10px', maxWidth: 260, overflowWrap: 'anywhere', fontFamily: 'JetBrains Mono, monospace' }}>
                    {item.filename || (item.status === 'unavailable' ? 'Capture unavailable' : item.status === 'failed' ? 'Capture transfer failed' : `Evidence #${item.file_id}`)}
                    {item.error_message && <div style={{ marginTop: 5, color: '#9aa39c', fontFamily: 'inherit', lineHeight: 1.4 }}>{item.error_message}</div>}
                    {item.collector_file_id && <details style={{ marginTop: 6, fontFamily: 'inherit' }}>
                      <summary style={{ color: '#9aa39c', cursor: 'pointer' }}>Capture metadata</summary>
                      <dl style={{ display: 'grid', gridTemplateColumns: 'auto 1fr', gap: '4px 10px', margin: '7px 0 0', fontFamily: 'JetBrains Mono, monospace', fontSize: 10, overflowWrap: 'anywhere' }}>
                        <dt>Trigger</dt><dd style={{ margin: 0 }}>{item.capture_trigger_type || '—'}</dd>
                        <dt>Interface</dt><dd style={{ margin: 0 }}>{item.capture_interface || '—'}</dd>
                        <dt>Snap length</dt><dd style={{ margin: 0 }}>{item.snaplen == null ? '—' : `${formatNumber(item.snaplen, 0)} bytes`}</dd>
                        <dt>Packets</dt><dd style={{ margin: 0 }}>{item.packet_count == null ? '—' : formatNumber(item.packet_count, 0)}</dd>
                        <dt>Original size</dt><dd style={{ margin: 0 }}>{item.original_size_bytes == null ? '—' : formatBytes(item.original_size_bytes)}</dd>
                        <dt>Compression</dt><dd style={{ margin: 0 }}>{item.compression || '—'}</dd>
                        <dt>SHA-256</dt><dd style={{ margin: 0 }}>{item.sha256 || item.collector_sha256 || (item.hash_status === 'pending' ? 'Pending' : 'Unavailable')}</dd>
                      </dl>
                    </details>}
                  </td>
                  <td style={{ padding: '10px', whiteSpace: 'nowrap' }}>{item.size_bytes == null ? '—' : formatBytes(item.size_bytes)}</td>
                  <td style={{ padding: '10px', whiteSpace: 'nowrap' }}>{item.duration_seconds == null ? '—' : formatDuration(item.duration_seconds * 1000)}</td>
                  <td style={{ padding: '10px', whiteSpace: 'nowrap' }}>{formatDateTime(item.capture_started_at || item.snapshot_created_at || item.captured_at)}</td>
                  <td style={{ padding: '10px' }}><Status value={item.transfer_status || item.status} /></td>
                  <td style={{ padding: '10px' }}>
                    <Status value={item.analysis_status || 'not_started'} />
                    {item.analysis_current_step && <div style={{ color: '#8b93a0', fontSize: 10, marginTop: 5 }}>{item.analysis_current_step.replaceAll('_', ' ')}</div>}
                  </td>
                  <td style={{ padding: '8px 10px', whiteSpace: 'nowrap' }}>
                    {item.download_available ? (
                      <a
                        href={api.investigationEvidenceDownloadUrl(investigation.id, item.file_id)}
                        aria-label={`Download ${item.filename || `PCAP evidence ${item.file_id}`}`}
                        style={{ display: 'inline-flex', alignItems: 'center', minHeight: 36, padding: '6px 10px', border: '1px solid #355a3c', borderRadius: 4, background: '#17251a', color: '#c6ff00', fontSize: 11, fontWeight: 700, textDecoration: 'none' }}
                      >Download</a>
                    ) : item.status === 'failed' && item.retry_available && CAN_WRITE ? (
                      <button type="button" onClick={() => retryTransfer(item.file_id)} disabled={retrying.has(item.file_id)} style={{ minHeight: 36, padding: '6px 10px', border: '1px solid #785215', borderRadius: 4, background: '#211b10', color: '#fbbf24', cursor: 'pointer', fontSize: 11, fontWeight: 700 }}>
                        {retrying.has(item.file_id) ? 'Retrying…' : 'Retry transfer'}
                      </button>
                    ) : <span style={{ color: '#7c8580', fontSize: 10 }}>{item.status === 'unavailable' ? 'Unavailable' : item.status === 'complete' ? 'Stored file missing' : 'Not ready'}</span>}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {showAnalysis && <InvestigationAnalysis investigation={investigation} refreshMs={refreshMs} onToast={(message, isError) => {
        if (isError) setActionError(message);
        else setActionMessage(message);
      }} />}
    </section>
  );
}
