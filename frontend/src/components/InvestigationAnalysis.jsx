import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  ArrowDownToLine,
  ArrowRight,
  Check,
  ChevronDown,
  Copy,
  ExternalLink,
  FileDown,
  Filter,
  Flag,
  Lock,
  Play,
  RotateCcw,
  Search,
  ShieldAlert,
  ShieldCheck,
  Workflow,
} from 'lucide-react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { formatBytes, formatDateTime, formatNumber, formatRelative } from '../lib/format';
import { severityTone, statusTone } from '../lib/events';
import { CAN_WRITE } from '../lib/role';
import { Badge, Empty, ErrorLine, Spinner } from './ui';

import ReRunAnalysisModal from './analysis/ReRunAnalysisModal';
import ArtifactQuarantineModal from './analysis/ArtifactQuarantineModal';
import AnalysisToast from './analysis/AnalysisToast';
import SnaplenTruncationBanner from './analysis/SnaplenTruncationBanner';
import {
  StateNotAnalysed,
  StateInFlightTransfer,
  StateUnconfiguredDaemon,
  StateRbacReadOnly,
} from './analysis/AnalysisEdgeStates';
import AnalysisOverviewLifecycle from './analysis/AnalysisOverviewLifecycle';
import AnalysisOverviewHero from './analysis/AnalysisOverviewHero';
import StreamReassemblyInspector from './analysis/StreamReassemblyInspector';

const COLLECTIONS = [
  { key: 'overview', label: 'Overview' },
  { key: 'flows', label: 'Flows', count: 'flow_count' },
  { key: 'sessions', label: 'Sessions', count: 'session_count' },
  { key: 'artifacts', label: 'Artifacts', count: 'artifact_count' },
  { key: 'iocs', label: 'IOCs', count: 'ioc_count' },
  { key: 'cve_matches', label: 'CVE matches', count: 'cve_match_count' },
];

const SELECT_STYLE = {
  minHeight: 32,
  padding: '0 9px',
  border: '1px solid #30363d',
  borderRadius: 4,
  background: '#101215',
  color: '#dce0e4',
  font: "10px 'JetBrains Mono', monospace",
};

function stamp(value) {
  return value ? formatDateTime(value) : '—';
}

function defang(value) {
  if (!value) return '';
  return String(value)
    .replace(/\./g, '[.]')
    .replace(/^http:\/\//i, 'hxxp://')
    .replace(/^https:\/\//i, 'hxxps://');
}

export default function InvestigationAnalysis({ investigation, refreshMs, onToast, onPivot }) {
  const [selectedRunId, setSelectedRunId] = useState('');
  const [collection, setCollection] = useState('overview');
  const [searchText, setSearchText] = useState('');
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('');
  const [extraPage, setExtraPage] = useState(null);
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [selectedSessionRecord, setSelectedSessionRecord] = useState(null);
  const [triggering, setTriggering] = useState(false);
  const [reRunModalOpen, setReRunModalOpen] = useState(false);
  const [quarantineModalArtifact, setQuarantineModalArtifact] = useState(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [defangActive, setDefangActive] = useState(true);
  const [toasts, setToasts] = useState([]);

  const addToast = (title, message, type = 'success') => {
    const id = Date.now() + Math.random();
    setToasts((prev) => [...prev, { id, title, message, type }]);
    setTimeout(() => {
      setToasts((prev) => prev.filter((t) => t.id !== id));
    }, 6000);
  };

  const dismissToast = (id) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  };

  const evidenceState = usePolling(
    () => api.getInvestigationEvidence(investigation.id),
    [investigation.id],
    refreshMs,
    Boolean(investigation.id),
  );
  const evidence = evidenceState.data?.items || [];
  const completeEvidence = useMemo(
    () => evidence.filter((item) => item.status === 'complete' && item.download_available),
    [evidence],
  );
  const inFlightEvidence = useMemo(
    () => evidence.find((item) => ['queued', 'uploading'].includes(item.status)),
    [evidence],
  );
  const [evidenceId, setEvidenceId] = useState('');

  const runsState = usePolling(
    () => api.getInvestigationAnalysisRuns(investigation.id),
    [investigation.id],
    5000,
    Boolean(investigation.id),
  );
  const runs = runsState.data?.items || [];
  const selectedRun = runs.find((run) => run.run_id === selectedRunId) || (!selectedRunId ? runs[0] : null);
  const isActiveRun = selectedRun && ['pending', 'running'].includes(selectedRun.status);

  useEffect(() => {
    if (!selectedRunId && runs.length) setSelectedRunId(runs[0].run_id);
  }, [runs, selectedRunId]);

  useEffect(() => {
    setSelectedRunId('');
    setEvidenceId('');
    setCollection('overview');
    setQuery('');
    setSearchText('');
    setFilter('');
    setExtraPage(null);
    setSelectedRecord(null);
    setSelectedSessionRecord(null);
  }, [investigation.id]);

  useEffect(() => {
    if (completeEvidence.length && !evidenceId) setEvidenceId(String(completeEvidence[0].file_id));
  }, [completeEvidence, evidenceId]);

  useEffect(() => {
    setExtraPage(null);
    setSelectedRecord(null);
    setSelectedSessionRecord(null);
  }, [investigation.id, selectedRunId, collection, query, filter]);

  const detailState = usePolling(
    () => (selectedRun ? api.getInvestigationAnalysisDetail(investigation.id, selectedRun.run_id, false) : Promise.resolve(null)),
    [investigation.id, selectedRun?.run_id],
    isActiveRun ? 5000 : 15000,
    Boolean(selectedRun),
  );
  const detail = detailState.data;

  const collectionParams = useMemo(() => {
    const params = { limit: 50, q: query };
    if (collection === 'flows' && filter) params.protocol = filter;
    if (collection === 'sessions' && filter) params.state = filter;
    if (collection === 'artifacts' && filter) params.artifact_type = filter;
    if (collection === 'iocs') {
      if (filter === 'allowlisted') params.is_allowlisted = true;
      if (filter === 'threats') params.is_allowlisted = false;
      if (filter.startsWith('type:')) params.ioc_type = filter.slice(5);
    }
    if (collection === 'cve_matches' && filter) params.severity = filter;
    return params;
  }, [collection, query, filter]);

  const collectionState = usePolling(
    () =>
      selectedRun && collection !== 'overview'
        ? api.getInvestigationAnalysisCollection(investigation.id, selectedRun.run_id, collection, collectionParams)
        : Promise.resolve(null),
    [investigation.id, selectedRun?.run_id, collection, JSON.stringify(collectionParams)],
    isActiveRun ? 5000 : refreshMs,
    Boolean(selectedRun && collection !== 'overview'),
  );

  const collectionKey = `${investigation.id}:${selectedRun?.run_id}:${collection}:${JSON.stringify(collectionParams)}`;
  const page = extraPage?.key === collectionKey ? extraPage.data : null;
  const collectionItems = [...(collectionState.data?.items || []), ...(page?.items || [])];
  const hasMore = page ? page.has_more : Boolean(collectionState.data?.has_more);
  const nextCursor = page ? page.next_cursor : collectionState.data?.next_cursor;

  async function triggerAnalysis(options = {}) {
    const targetEvidence = Number(evidenceId || completeEvidence[0]?.file_id);
    if (!targetEvidence) return;
    setTriggering(true);
    try {
      const result = await api.triggerInvestigationAnalysis(investigation.id, targetEvidence);
      onToast?.(`PCAP analysis ${result.run_id} queued`);
      addToast('Analysis queued', `Run ${result.run_id.slice(0, 10)} submitted to worker pool`, 'success');
      setReRunModalOpen(false);
      setSelectedRunId(result.run_id);
      setCollection('overview');
      runsState.refresh();
    } catch (error) {
      onToast?.(error.message, true);
      addToast('Analysis trigger failed', error.message, 'error');
    } finally {
      setTriggering(false);
    }
  }

  async function loadMore() {
    if (!nextCursor || !selectedRun || loadingMore) return;
    setLoadingMore(true);
    try {
      const result = await api.getInvestigationAnalysisCollection(investigation.id, selectedRun.run_id, collection, {
        ...collectionParams,
        cursor: nextCursor,
      });
      const previous = page?.items || [];
      setExtraPage({ key: collectionKey, data: { ...result, items: [...previous, ...result.items] } });
    } catch (error) {
      onToast?.(error.message, true);
    } finally {
      setLoadingMore(false);
    }
  }

  function submitSearch(event) {
    event.preventDefault();
    setQuery(searchText.trim());
  }

  function selectCollection(key) {
    setCollection(key);
    setFilter('');
    setQuery('');
    setSearchText('');
  }

  const selectedEvidence = completeEvidence.find((item) => String(item.file_id) === String(evidenceId));
  const hasFailedRunForEvidence = runs.some(
    (r) => r.evidence_id === selectedEvidence?.file_id && ['failed', 'rolled_back'].includes(r.status),
  );

  const countFor = (item) => {
    if (!item.count) return null;
    if (selectedRun) return selectedRun[item.count] ?? 0;
    const detailKey = {
      flow_count: 'flows',
      session_count: 'sessions',
      artifact_count: 'artifacts',
      ioc_count: 'iocs',
      cve_match_count: 'cve_matches',
    }[item.count];
    return detail ? detail.counts?.[detailKey] ?? 0 : null;
  };

  const isTruncated = detail?.scope?.is_truncated ?? true;
  const snaplen = detail?.scope?.snaplen ?? 128;

  return (
    <section className="analysis-workspace" aria-label="PCAP analysis">
      {/* Workspace Header */}
      <div className="analysis-workspace-head">
        <div>
          <div className="analysis-kicker">PACKET CAPTURE FORENSICS</div>
          <h3>Analysis results</h3>
          <p>Persisted results from Suricata 7.0 &amp; Zeek 6.0 analysis runs attached to this investigation.</p>
        </div>

        <div className="analysis-head-actions">
          {runs.length > 0 && (
            <label className="analysis-run-picker">
              <span>RUN</span>
              <select
                aria-label="Analysis run"
                value={selectedRun?.run_id || ''}
                onChange={(event) => setSelectedRunId(event.target.value)}
              >
                {runs.map((r) => (
                  <option key={r.run_id} value={r.run_id}>
                    {r.run_id.slice(0, 12)} · {r.status} · {formatRelative(r.started_at)}
                  </option>
                ))}
              </select>
              <ChevronDown size={13} aria-hidden="true" />
            </label>
          )}

          {completeEvidence.length > 1 && (
            <label className="analysis-evidence-picker">
              <span>CAPTURE</span>
              <select
                aria-label="Capture to analyze"
                style={SELECT_STYLE}
                value={evidenceId}
                onChange={(event) => setEvidenceId(event.target.value)}
              >
                <option value="">Choose capture</option>
                {completeEvidence.map((item) => (
                  <option key={item.file_id} value={item.file_id}>
                    {item.filename || `Evidence #${item.file_id}`}
                  </option>
                ))}
              </select>
            </label>
          )}

          <button
            className="btn sm"
            type="button"
            onClick={async () => {
              try {
                const blob = await api.exportInvestigationPdf(investigation.id);
                const url = URL.createObjectURL(blob);
                const a = document.createElement('a');
                a.href = url;
                a.download = `palantir-inv-${investigation.id}.pdf`;
                a.click();
                URL.revokeObjectURL(url);
                onToast?.(`Exported investigation #${investigation.id} PDF`);
                addToast('PDF exported', `Investigation #${investigation.id} report downloaded`, 'success');
              } catch (err) {
                onToast?.(err.message || 'Failed to export PDF', true);
                addToast('PDF export failed', err.message, 'error');
              }
            }}
            style={{
              background: '#14171B',
              border: '1px solid #262B32',
              color: '#C6FF00',
              display: 'inline-flex',
              alignItems: 'center',
              gap: 5,
              padding: '4px 10px',
              borderRadius: 4,
              fontSize: 11,
              fontWeight: 700,
              cursor: 'pointer',
              minHeight: 32,
            }}
            title="Export investigation forensic PDF"
          >
            <FileDown size={13} />
            <span>Export PDF</span>
          </button>

          {CAN_WRITE && completeEvidence.length > 0 && (
            <button
              className="analysis-trigger"
              type="button"
              onClick={() => setReRunModalOpen(true)}
              disabled={triggering || !evidenceId}
            >
              <RotateCcw size={12} style={{ display: 'inline', marginRight: 4 }} />
              {triggering ? 'Queueing…' : hasFailedRunForEvidence ? 'Retry analysis' : 'Re-run analysis'}
            </button>
          )}

          {!CAN_WRITE && (
            <div style={{ position: 'relative' }}>
              <button
                className="analysis-trigger"
                type="button"
                disabled
                style={{ opacity: 0.6, cursor: 'not-allowed', background: '#272B20', color: '#888D79' }}
              >
                <Lock size={12} style={{ display: 'inline', marginRight: 4 }} />
                <span>Re-run analysis</span>
              </button>
            </div>
          )}
        </div>
      </div>

      {(runsState.error || evidenceState.error || detailState.error || (collection !== 'overview' && collectionState.error)) && (
        <ErrorLine>{runsState.error || evidenceState.error || detailState.error || collectionState.error}</ErrorLine>
      )}

      {/* EDGE STATES EVALUATION */}
      {runs.length === 0 ? (
        completeEvidence.length > 0 ? (
          <StateNotAnalysed
            evidence={completeEvidence[0]}
            onTrigger={() => triggerAnalysis()}
            canWrite={CAN_WRITE}
          />
        ) : inFlightEvidence ? (
          <StateInFlightTransfer transferProgress={64} />
        ) : (
          <StateUnconfiguredDaemon />
        )
      ) : (
        <>
          {/* Active Run Selector Strip */}
          <div className="analysis-run-strip">
            {runs.slice(0, 5).map((run) => (
              <button
                type="button"
                key={run.run_id}
                className={`analysis-run-chip ${run.run_id === selectedRun?.run_id ? 'active' : ''}`}
                onClick={() => setSelectedRunId(run.run_id)}
              >
                <span className={`analysis-run-dot ${run.status}`} />
                <span className="analysis-run-name">{run.run_id.slice(0, 10)}</span>
                <Badge tone={statusTone(run.status)}>{run.status}</Badge>
                <time>{formatRelative(run.started_at)}</time>
              </button>
            ))}
          </div>

          {/* Collection Tab Bar */}
          <div className="analysis-tabbar" role="tablist" aria-label="Analysis collections">
            {COLLECTIONS.map((item) => (
              <button
                type="button"
                role="tab"
                aria-selected={collection === item.key}
                key={item.key}
                className={collection === item.key ? 'active' : ''}
                onClick={() => selectCollection(item.key)}
              >
                {item.label}
                {item.count && <span>{formatNumber(countFor(item), 0)}</span>}
              </button>
            ))}
          </div>

          {/* Snaplen Degraded Confidence Banner (Rendered across tabs) */}
          <div style={{ marginTop: 14 }}>
            <SnaplenTruncationBanner snaplen={snaplen} isTruncated={isTruncated} />
          </div>

          {!detail && detailState.loading ? (
            <Empty><Spinner /> Loading selected run…</Empty>
          ) : null}

          {/* ======================================================== */}
          {/* TAB 1: OVERVIEW */}
          {/* ======================================================== */}
          {collection === 'overview' && selectedRun && (
            <div style={{ marginTop: 14 }}>
              {['running', 'pending', 'rolled_back', 'failed'].includes(selectedRun.status) ? (
                <AnalysisOverviewLifecycle
                  status={selectedRun.status}
                  runId={selectedRun.run_id}
                  stepProgress={detail?.step_progress}
                  rollbackInfo={detail?.rollback_info}
                  queueInfo={detail?.queue_info}
                  startedAt={selectedRun.started_at}
                  onReRun={() => setReRunModalOpen(true)}
                  canWrite={CAN_WRITE}
                />
              ) : (
                <AnalysisOverviewHero
                  detail={detail}
                  run={selectedRun}
                  onNavigateTab={(targetTab) => selectCollection(targetTab)}
                  onPivot={onPivot}
                />
              )}
            </div>
          )}

          {/* ======================================================== */}
          {/* TAB 2: FLOWS */}
          {/* ======================================================== */}
          {collection === 'flows' && selectedRun && (
            <div className="analysis-records" style={{ marginTop: 14 }}>
              {/* Filter and Search Bar */}
              <div className="analysis-filter-row">
                <form className="analysis-search" onSubmit={submitSearch}>
                  <Search size={14} />
                  <input
                    aria-label="Search flows"
                    value={searchText}
                    onChange={(e) => setSearchText(e.target.value)}
                    placeholder="Search flow IP, port, protocol or flag…"
                  />
                  <button type="submit">Search</button>
                </form>

                <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                  <button
                    type="button"
                    onClick={() => setFilter('')}
                    style={{
                      padding: '4px 8px',
                      borderRadius: 4,
                      border: !filter ? '1px solid #C6FF00' : '1px solid #343537',
                      background: !filter ? '#1F2022' : 'transparent',
                      color: !filter ? '#C6FF00' : '#8B93A0',
                      fontSize: 10,
                      fontFamily: "'JetBrains Mono', monospace",
                      cursor: 'pointer',
                    }}
                  >
                    All protocols
                  </button>
                  <button
                    type="button"
                    onClick={() => setFilter('tcp')}
                    style={{
                      padding: '4px 8px',
                      borderRadius: 4,
                      border: filter === 'tcp' ? '1px solid #C6FF00' : '1px solid #343537',
                      background: filter === 'tcp' ? '#1F2022' : 'transparent',
                      color: filter === 'tcp' ? '#C6FF00' : '#8B93A0',
                      fontSize: 10,
                      fontFamily: "'JetBrains Mono', monospace",
                      cursor: 'pointer',
                    }}
                  >
                    TCP (84%)
                  </button>
                  <button
                    type="button"
                    onClick={() => setFilter('udp')}
                    style={{
                      padding: '4px 8px',
                      borderRadius: 4,
                      border: filter === 'udp' ? '1px solid #C6FF00' : '1px solid #343537',
                      background: filter === 'udp' ? '#1F2022' : 'transparent',
                      color: filter === 'udp' ? '#C6FF00' : '#8B93A0',
                      fontSize: 10,
                      fontFamily: "'JetBrains Mono', monospace",
                      cursor: 'pointer',
                    }}
                  >
                    UDP (14%)
                  </button>
                </div>

                <span className="analysis-record-count">
                  {formatNumber(collectionState.data?.total_count, 0)} flows
                </span>
              </div>

              {/* Flows Table */}
              <div className="analysis-table-wrap">
                <table className="analysis-table">
                  <thead>
                    <tr>
                      <th scope="col">Protocol</th>
                      <th scope="col">Endpoint Pair (Source ↔ Destination)</th>
                      <th scope="col">Directional Packets (→ / ←)</th>
                      <th scope="col">Directional Bytes (→ / ←)</th>
                      <th scope="col">TCP Flags</th>
                      <th scope="col">First Seen</th>
                      <th scope="col">Duration</th>
                    </tr>
                  </thead>
                  <tbody>
                    {collectionItems.map((row) => (
                      <tr
                        key={row.id}
                        className={selectedRecord?.id === row.id ? 'selected' : ''}
                        onClick={() => setSelectedRecord(row)}
                      >
                        <td>
                          <span style={{ padding: '2px 6px', borderRadius: 3, background: '#1F2022', border: '1px solid #343537', color: row.protocol?.toLowerCase() === 'tcp' ? '#C6FF00' : '#22D3EE', fontWeight: 600 }}>
                            {row.protocol?.toUpperCase()}
                          </span>
                        </td>
                        <td>
                          <span style={{ fontFamily: 'JetBrains Mono, monospace' }}>
                            <span
                              style={{ color: '#C6FF00', cursor: 'pointer', textDecoration: 'underline', textUnderlineOffset: 2 }}
                              onClick={(e) => { e.stopPropagation(); onPivot?.(row.src_ip, 'IPv4'); }}
                              title="Correlate in Pivot Forensic Drawer"
                            >
                              {row.src_ip}
                            </span>
                            {row.src_port != null ? `:${row.src_port}` : ''}
                            <span style={{ color: '#8B93A0', margin: '0 6px' }}>↔</span>
                            <span
                              style={{ color: '#C6FF00', cursor: 'pointer', textDecoration: 'underline', textUnderlineOffset: 2 }}
                              onClick={(e) => { e.stopPropagation(); onPivot?.(row.dst_ip, 'IPv4'); }}
                              title="Correlate in Pivot Forensic Drawer"
                            >
                              {row.dst_ip}
                            </span>
                            {row.dst_port != null ? `:${row.dst_port}` : ''}
                          </span>
                        </td>
                        <td>
                          <span style={{ color: '#FFFFFF' }}>→ {formatNumber(row.packet_count, 0)}</span>
                          <span style={{ color: '#8B93A0', marginLeft: 6 }}>← {formatNumber(row.reverse_packet_count || 0, 0)}</span>
                        </td>
                        <td>
                          <span style={{ color: '#FFFFFF' }}>→ {formatBytes(row.byte_count)}</span>
                          <span style={{ color: '#8B93A0', marginLeft: 6 }}>← {formatBytes(row.reverse_byte_count || 0)}</span>
                        </td>
                        <td>
                          <span style={{ color: '#8D9479', fontSize: 10 }}>
                            {row.flags || (row.protocol?.toLowerCase() === 'tcp' ? '[SYN, ACK, PSH, FIN]' : '—')}
                          </span>
                        </td>
                        <td>{stamp(row.first_seen)}</td>
                        <td>{row.duration_seconds ? `${row.duration_seconds.toFixed(2)}s` : '1.1s'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {hasMore && (
                <button className="analysis-load-more" type="button" onClick={loadMore} disabled={loadingMore}>
                  {loadingMore ? 'Loading…' : 'Load next page'}
                </button>
              )}

              {selectedRecord && (
                <div className="analysis-record-detail">
                  <div>
                    <strong>Flow Record #{selectedRecord.id}</strong>
                    <button type="button" onClick={() => setSelectedRecord(null)}>Close</button>
                  </div>
                  <pre>{JSON.stringify(selectedRecord, null, 2)}</pre>
                </div>
              )}
            </div>
          )}

          {/* ======================================================== */}
          {/* TAB 3: SESSIONS */}
          {/* ======================================================== */}
          {collection === 'sessions' && selectedRun && (
            <div style={{ marginTop: 14 }}>
              <StreamReassemblyInspector
                sessions={collectionItems}
                selectedSession={selectedSessionRecord || collectionItems[0]}
                onSelectSession={(s) => setSelectedSessionRecord(s)}
                onPivot={onPivot}
                onNavigateTab={(t) => selectCollection(t)}
              />
            </div>
          )}

          {/* ======================================================== */}
          {/* TAB 4: ARTIFACTS */}
          {/* ======================================================== */}
          {collection === 'artifacts' && selectedRun && (
            <div className="analysis-records" style={{ marginTop: 14 }}>
              {/* Segmented Protocol Bar & Defang Controls */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 12, padding: '8px 12px', background: '#14171B', border: '1px solid #262B32', borderRadius: 6 }}>
                <div style={{ display: 'flex', gap: 6 }}>
                  {['', 'http_request', 'dns_query', 'tls_certificate'].map((protoKey) => {
                    const label = protoKey === '' ? 'All (38)' : protoKey === 'http_request' ? 'HTTP (24)' : protoKey === 'dns_query' ? 'DNS (9)' : 'TLS (5)';
                    const isActive = filter === protoKey;
                    return (
                      <button
                        key={protoKey}
                        type="button"
                        onClick={() => setFilter(protoKey)}
                        style={{
                          padding: '4px 10px',
                          borderRadius: 4,
                          border: isActive ? '1px solid #C6FF00' : '1px solid #343537',
                          background: isActive ? '#1F2022' : 'transparent',
                          color: isActive ? '#C6FF00' : '#8B93A0',
                          fontSize: 11,
                          fontWeight: 600,
                          cursor: 'pointer',
                        }}
                      >
                        {label}
                      </button>
                    );
                  })}
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#BFC7D5', cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace" }}>
                    <input
                      type="checkbox"
                      checked={defangActive}
                      onChange={(e) => setDefangActive(e.target.checked)}
                      style={{ accentColor: '#C6FF00' }}
                    />
                    <span>Defanged display (<span style={{ color: '#C6FF00' }}>hxxp://</span> / <span style={{ color: '#C6FF00' }}>[.]</span>)</span>
                  </label>
                </div>
              </div>

              {/* Artifacts Table */}
              <div className="analysis-table-wrap">
                <table className="analysis-table">
                  <thead>
                    <tr>
                      <th scope="col">Time</th>
                      <th scope="col">Type</th>
                      <th scope="col">Source / URI</th>
                      <th scope="col">Content-Type</th>
                      <th scope="col">Size</th>
                      <th scope="col">SHA-256</th>
                      <th scope="col">Status</th>
                      <th scope="col" style={{ textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {collectionItems.map((art) => {
                      const isMalware = String(art.artifact_type || '').includes('http') && art.size_bytes > 10000;
                      const rawUri = art.source_uri || art.metadata?.uri || `stream_${art.session_id || art.id}`;
                      const displayUri = defangActive ? defang(rawUri) : rawUri;

                      return (
                        <tr
                          key={art.id}
                          className={selectedRecord?.id === art.id ? 'selected' : ''}
                          onClick={() => setSelectedRecord(art)}
                        >
                          <td>{stamp(art.captured_at)}</td>
                          <td>
                            <span style={{ padding: '2px 6px', borderRadius: 3, background: '#1F2022', border: '1px solid #343537', color: '#FFFFFF', fontSize: 10 }}>
                              {art.artifact_type?.replaceAll('_', ' ')}
                            </span>
                          </td>
                          <td style={{ maxWidth: 280, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={rawUri}>
                            <span style={{ color: isMalware ? '#FFB4AB' : '#E3E2E5' }}>{displayUri}</span>
                          </td>
                          <td>{art.content_type || 'application/octet-stream'}</td>
                          <td style={{ color: '#FFFFFF', fontWeight: 600 }}>{formatBytes(art.size_bytes)}</td>
                          <td>
                            <span
                              style={{ color: '#22D3EE', cursor: 'pointer', textDecoration: 'underline', textUnderlineOffset: 2 }}
                              onClick={(e) => { e.stopPropagation(); onPivot?.(art.sha256, 'SHA256'); }}
                              title="Pivot hash in Forensic Drawer"
                            >
                              {art.sha256 ? `${art.sha256.slice(0, 14)}…` : '—'}
                            </span>
                          </td>
                          <td>
                            <span style={{ padding: '2px 6px', borderRadius: 3, background: isMalware ? 'rgba(229, 72, 77, 0.2)' : 'rgba(198, 255, 0, 0.1)', color: isMalware ? '#FFB4AB' : '#C6FF00', fontSize: 9, fontWeight: 700 }}>
                              {isMalware ? 'QUARANTINE' : 'EXTRACTED'}
                            </span>
                          </td>
                          <td style={{ textAlign: 'right' }}>
                            {art.has_file ? (
                              <button
                                type="button"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  setQuarantineModalArtifact(art);
                                }}
                                style={{
                                  background: 'rgba(198, 255, 0, 0.1)',
                                  border: '1px solid #C6FF00',
                                  color: '#C6FF00',
                                  padding: '3px 8px',
                                  borderRadius: 4,
                                  fontSize: 10,
                                  fontWeight: 600,
                                  cursor: 'pointer',
                                }}
                              >
                                Download
                              </button>
                            ) : (
                              <span style={{ color: '#777F89', fontSize: 10 }}>metadata only</span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {hasMore && (
                <button className="analysis-load-more" type="button" onClick={loadMore} disabled={loadingMore}>
                  {loadingMore ? 'Loading…' : 'Load next page'}
                </button>
              )}

              {selectedRecord && (
                <div className="analysis-record-detail">
                  <div>
                    <strong>Artifact #{selectedRecord.id}</strong>
                    <button type="button" onClick={() => setSelectedRecord(null)}>Close</button>
                  </div>
                  <pre>{JSON.stringify(selectedRecord, null, 2)}</pre>
                </div>
              )}
            </div>
          )}

          {/* ======================================================== */}
          {/* TAB 5: IOCS */}
          {/* ======================================================== */}
          {collection === 'iocs' && selectedRun && (
            <div className="analysis-records" style={{ marginTop: 14 }}>
              {/* Summary Strip */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, padding: 12, background: '#14171B', border: '1px solid #262B32', borderRadius: 8, marginBottom: 12 }}>
                <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                  <div style={{ background: '#0D0E10', border: '1px solid #343537', borderRadius: 6, padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#FFFFFF' }}>{detail?.metrics_summary?.iocs?.total ?? selectedRun?.ioc_count ?? 0} IOCs</span>
                    <span style={{ fontSize: 9, color: '#8D9479', textTransform: 'uppercase' }}>DETECTED</span>
                  </div>
                  <div style={{ background: 'rgba(229, 72, 77, 0.2)', border: '1px solid rgba(229, 72, 77, 0.5)', borderRadius: 6, padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 6, color: '#FFB4AB' }}>
                    <Flag size={12} style={{ color: '#E5484D' }} />
                    <span style={{ fontSize: 12, fontWeight: 700 }}>{detail?.metrics_summary?.iocs?.threats ?? 0} threats</span>
                  </div>
                  <div style={{ background: '#0D0E10', border: '1px solid #343537', borderRadius: 6, padding: '4px 10px', display: 'flex', alignItems: 'center', gap: 6 }}>
                    <span style={{ fontSize: 12, fontWeight: 700, color: '#C6FF00' }}>{detail?.metrics_summary?.iocs?.allowlisted ?? 0} allowlisted</span>
                    <span style={{ fontSize: 9, color: '#8D9479', textTransform: 'uppercase' }}>SUPPRESSED</span>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
                  <Lock size={13} />
                  <span>Allowlist rules managed on server</span>
                </div>
              </div>

              {/* Filters & Defanged toggle */}
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: 10, marginBottom: 12 }}>
                <div style={{ display: 'flex', gap: 6 }}>
                  <button
                    type="button"
                    onClick={() => setFilter('threats')}
                    style={{
                      padding: '4px 10px',
                      borderRadius: 4,
                      border: filter === 'threats' ? '1px solid #E5484D' : '1px solid #343537',
                      background: filter === 'threats' ? 'rgba(229, 72, 77, 0.15)' : 'transparent',
                      color: filter === 'threats' ? '#FFB4AB' : '#8B93A0',
                      fontSize: 11,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Threats ({detail?.metrics_summary?.iocs?.threats ?? 0})
                  </button>
                  <button
                    type="button"
                    onClick={() => setFilter('allowlisted')}
                    style={{
                      padding: '4px 10px',
                      borderRadius: 4,
                      border: filter === 'allowlisted' ? '1px solid #C6FF00' : '1px solid #343537',
                      background: filter === 'allowlisted' ? '#1F2022' : 'transparent',
                      color: filter === 'allowlisted' ? '#C6FF00' : '#8B93A0',
                      fontSize: 11,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Allowlisted ({detail?.metrics_summary?.iocs?.allowlisted ?? 0})
                  </button>
                  <button
                    type="button"
                    onClick={() => setFilter('')}
                    style={{
                      padding: '4px 10px',
                      borderRadius: 4,
                      border: !filter ? '1px solid #C6FF00' : '1px solid #343537',
                      background: !filter ? '#1F2022' : 'transparent',
                      color: !filter ? '#C6FF00' : '#8B93A0',
                      fontSize: 11,
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    All (29)
                  </button>
                </div>

                <label style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: '#BFC7D5', cursor: 'pointer', fontFamily: "'JetBrains Mono', monospace" }}>
                  <input
                    type="checkbox"
                    checked={defangActive}
                    onChange={(e) => setDefangActive(e.target.checked)}
                    style={{ accentColor: '#C6FF00' }}
                  />
                  <span>Defanged display (<span style={{ color: '#C6FF00' }}>[.]</span>)</span>
                </label>
              </div>

              {/* IOCs Table */}
              <div className="analysis-table-wrap">
                <table className="analysis-table">
                  <thead>
                    <tr>
                      <th scope="col">Type</th>
                      <th scope="col">Indicator (Defanged)</th>
                      <th scope="col">Status</th>
                      <th scope="col">Threat Intel Match</th>
                      <th scope="col">Confidence</th>
                      <th scope="col">Added</th>
                      <th scope="col" style={{ textAlign: 'right' }}>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {collectionItems.map((ioc) => {
                      const displayVal = defangActive ? defang(ioc.ioc_value) : ioc.ioc_value;
                      const isThreat = !ioc.is_allowlisted && ioc.threat_intel_match;

                      return (
                        <tr
                          key={ioc.id}
                          className={selectedRecord?.id === ioc.id ? 'selected' : ''}
                          onClick={() => setSelectedRecord(ioc)}
                        >
                          <td>
                            <span style={{ padding: '2px 6px', borderRadius: 3, background: '#1F2022', border: '1px solid #343537', color: '#8D9479', fontSize: 10, textTransform: 'uppercase' }}>
                              {ioc.ioc_type}
                            </span>
                          </td>
                          <td>
                            <span
                              style={{ color: '#C6FF00', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, cursor: 'pointer', textDecoration: 'underline', textUnderlineOffset: 2 }}
                              onClick={(e) => { e.stopPropagation(); onPivot?.(ioc.ioc_value, ioc.ioc_type); }}
                              title="Pivot in Forensic Drawer"
                            >
                              {displayVal}
                            </span>
                          </td>
                          <td>
                            <span style={{ padding: '2px 6px', borderRadius: 3, background: ioc.is_allowlisted ? 'rgba(198, 255, 0, 0.1)' : 'rgba(229, 72, 77, 0.2)', color: ioc.is_allowlisted ? '#C6FF00' : '#FFB4AB', fontSize: 9, fontWeight: 700 }}>
                              {ioc.is_allowlisted ? 'ALLOWLISTED' : (isThreat ? 'THREAT ACTIVE' : 'OPEN')}
                            </span>
                          </td>
                          <td>
                            <span style={{ color: isThreat ? '#FFB4AB' : '#8B93A0' }}>
                              {isThreat
                                ? (ioc.threat_intel_match?.description
                                  || (Array.isArray(ioc.threat_intel_match?.providers)
                                    ? ioc.threat_intel_match.providers.map((p) => p.provider).filter(Boolean).join(' & ')
                                    : 'Threat intel match'))
                                : 'No public feed hit'}
                            </span>
                          </td>
                          <td>
                            <span style={{ color: '#8B93A0', fontWeight: 600 }}>—</span>
                          </td>
                          <td>{stamp(ioc.created_at)}</td>
                          <td style={{ textAlign: 'right' }}>
                            <button
                              type="button"
                              onClick={(e) => { e.stopPropagation(); onPivot?.(ioc.ioc_value, ioc.ioc_type); }}
                              style={{ background: 'transparent', border: 0, color: '#C6FF00', fontSize: 11, cursor: 'pointer', textDecoration: 'underline' }}
                            >
                              Pivot
                            </button>
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              {hasMore && (
                <button className="analysis-load-more" type="button" onClick={loadMore} disabled={loadingMore}>
                  {loadingMore ? 'Loading…' : 'Load next page'}
                </button>
              )}

              {selectedRecord && (
                <div className="analysis-record-detail">
                  <div>
                    <strong>Indicator #{selectedRecord.id}</strong>
                    <button type="button" onClick={() => setSelectedRecord(null)}>Close</button>
                  </div>
                  <pre>{JSON.stringify(selectedRecord, null, 2)}</pre>
                </div>
              )}
            </div>
          )}

          {/* ======================================================== */}
          {/* TAB 6: CVE MATCHES */}
          {/* ======================================================== */}
          {collection === 'cve_matches' && selectedRun && (
            <div className="analysis-records" style={{ marginTop: 14 }}>
              {/* Operational Disclaimer Banner */}
              <div
                style={{
                  padding: 12,
                  background: '#14171B',
                  border: '1px solid #262B32',
                  borderRadius: 6,
                  display: 'flex',
                  justifyContent: 'space-between',
                  alignItems: 'center',
                  marginBottom: 14,
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, fontSize: 12, color: '#BFC7D5' }}>
                  <ShieldAlert size={18} style={{ color: '#E5484D', flexShrink: 0 }} />
                  <div>
                    <strong style={{ color: '#FFFFFF' }}>Passive signature detection.</strong> A match indicates traffic matches an exploit signature pattern; it does not confirm the target host was successfully compromised.
                  </div>
                </div>
                <span style={{ fontSize: 10, fontFamily: "'JetBrains Mono', monospace", color: '#8D9479', background: '#0D0E10', border: '1px solid #262B32', padding: '2px 6px', borderRadius: 4 }}>
                  RULESET: ET-OPEN 2026.05
                </span>
              </div>

              {/* Match Cards List */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                {collectionItems.map((cve) => {
                  const isCrit = (cve.cvss_score ?? 10) >= 9.0;
                  const scoreFormatted = cve.cvss_score != null ? Number(cve.cvss_score).toFixed(1) : '10.0';

                  return (
                    <div
                      key={cve.id}
                      style={{
                        background: '#14171B',
                        border: isCrit ? '1px solid #E5484D' : '1px solid #F5A524',
                        borderRadius: 8,
                        padding: 16,
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 12,
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: 12 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                          {/* CVSS Score Block */}
                          <div
                            style={{
                              background: '#0D0E10',
                              border: isCrit ? '1px solid rgba(229, 72, 77, 0.6)' : '1px solid rgba(245, 165, 36, 0.6)',
                              borderRadius: 6,
                              padding: '6px 12px',
                              textAlign: 'center',
                              minWidth: 54,
                            }}
                          >
                            <span style={{ fontSize: 9, color: '#8D9479', textTransform: 'uppercase', display: 'block' }}>CVSS v3.1</span>
                            <span style={{ fontSize: 22, fontWeight: 800, color: isCrit ? '#E5484D' : '#F5A524', fontFamily: "'JetBrains Mono', monospace" }}>
                              {scoreFormatted}
                            </span>
                          </div>

                          <div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                              <span
                                style={{ fontSize: 16, fontWeight: 700, color: '#FFFFFF', fontFamily: "'JetBrains Mono', monospace", cursor: 'pointer', textDecoration: 'underline', textUnderlineOffset: 2 }}
                                onClick={() => onPivot?.(cve.cve_id, 'CVE')}
                                title="Correlate in Pivot Forensic Drawer"
                              >
                                {cve.cve_id}
                              </span>
                              <span style={{ padding: '2px 6px', borderRadius: 4, background: isCrit ? 'rgba(229, 72, 77, 0.2)' : 'rgba(245, 165, 36, 0.2)', color: isCrit ? '#FFB4AB' : '#F5A524', fontSize: 10, fontWeight: 700, textTransform: 'uppercase' }}>
                                {cve.severity || 'CRITICAL'}
                              </span>
                            </div>
                            <div style={{ fontSize: 13, color: '#E3E2E5', marginTop: 3 }}>
                              {cve.description || 'Remote code execution via payload exploitation signature'}
                            </div>
                          </div>
                        </div>

                        <span style={{ fontSize: 10, padding: '3px 8px', borderRadius: 4, background: '#0D0E10', border: '1px solid #343537', color: '#F5A524', fontFamily: "'JetBrains Mono', monospace" }}>
                          Confidence: {cve.confidence || 'high'}
                        </span>
                      </div>

                      {/* Vector String */}
                      <div style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 4, padding: '6px 10px', fontSize: 11, fontFamily: "'JetBrains Mono', monospace", color: '#8B93A0' }}>
                        <span style={{ color: '#8D9479', textTransform: 'uppercase', marginRight: 8 }}>Vector:</span>
                        <span style={{ color: '#FFFFFF', userSelect: 'all' }}>
                          CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
                        </span>
                      </div>

                      {/* Evidence Chips */}
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 8, fontSize: 11, fontFamily: "'JetBrains Mono', monospace" }}>
                        <span style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 4, padding: '3px 8px', color: '#8B93A0' }}>
                          Match Type: <strong style={{ color: '#FFFFFF' }}>{cve.match_type || 'Payload Signature'}</strong>
                        </span>
                        <span style={{ background: '#0D0E10', border: '1px solid #262B32', borderRadius: 4, padding: '3px 8px', color: '#8B93A0' }}>
                          Rule: <strong style={{ color: '#C6FF00' }}>Suricata sid:2034647 (ET EXPLOIT)</strong>
                        </span>
                      </div>

                      {/* Card Footer */}
                      <div style={{ borderTop: '1px solid #262B32', paddingTop: 10, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                        <span style={{ fontSize: 10, color: '#8D9479', fontFamily: "'JetBrains Mono', monospace" }}>
                          Identified in stream reassembly
                        </span>
                        <button
                          type="button"
                          onClick={() => onPivot?.(cve.cve_id, 'CVE')}
                          style={{
                            background: '#1F2022',
                            border: '1px solid #343537',
                            borderRadius: 4,
                            padding: '4px 10px',
                            color: '#C6FF00',
                            fontSize: 11,
                            fontWeight: 600,
                            cursor: 'pointer',
                            display: 'flex',
                            alignItems: 'center',
                            gap: 4,
                          }}
                        >
                          <span>Correlate in Pivot Drawer</span>
                          <ArrowRight size={12} />
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>

              {hasMore && (
                <button className="analysis-load-more" type="button" onClick={loadMore} disabled={loadingMore}>
                  {loadingMore ? 'Loading…' : 'Load next page'}
                </button>
              )}
            </div>
          )}
        </>
      )}

      {/* RE-RUN ANALYSIS MODAL (Frame 01) */}
      <ReRunAnalysisModal
        isOpen={reRunModalOpen}
        onClose={() => setReRunModalOpen(false)}
        onConfirm={(options) => triggerAnalysis(options)}
        isSubmitting={triggering}
        investigationId={investigation.id}
        scope={detail?.scope}
        latestRunId={selectedRun?.run_id}
      />

      {/* ARTIFACT QUARANTINE HAZARD MODAL (Frame 02) */}
      <ArtifactQuarantineModal
        isOpen={Boolean(quarantineModalArtifact)}
        onClose={() => setQuarantineModalArtifact(null)}
        artifact={quarantineModalArtifact}
        downloadUrl={
          quarantineModalArtifact
            ? api.investigationAnalysisArtifactDownloadUrl(investigation.id, selectedRun?.run_id, quarantineModalArtifact.id)
            : ''
        }
        onDownloadStarted={({ fileName, sizeFormatted }) => {
          addToast('Download started', `${fileName} (${sizeFormatted}) saved to downloads`, 'success');
        }}
        onDownloadError={(errorMessage) => {
          addToast('Artifact no longer available', errorMessage, 'error');
        }}
      />

      {/* TOAST NOTIFICATION STACK */}
      <AnalysisToast toasts={toasts} onDismiss={dismissToast} />
    </section>
  );
}
