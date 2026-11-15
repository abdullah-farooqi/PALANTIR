import { useEffect, useMemo, useState } from 'react';
import { ArrowDownToLine, ChevronDown, Search, ShieldAlert, Workflow } from 'lucide-react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { formatBytes, formatDateTime, formatNumber, formatRelative } from '../lib/format';
import { severityTone, statusTone } from '../lib/events';
import { CAN_WRITE } from '../lib/role';
import { Badge, Empty, ErrorLine, Spinner } from './ui';

const COLLECTIONS = [
  { key: 'overview', label: 'Overview' },
  { key: 'flows', label: 'Flows', count: 'flow_count' },
  { key: 'sessions', label: 'Sessions', count: 'session_count' },
  { key: 'artifacts', label: 'Artifacts', count: 'artifact_count' },
  { key: 'iocs', label: 'IOCs', count: 'ioc_count' },
  { key: 'cve_matches', label: 'CVE', count: 'cve_match_count' },
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

function endpoint(row) {
  return `${row.src_ip || '—'}${row.src_port == null ? '' : `:${row.src_port}`} → ${row.dst_ip || '—'}${row.dst_port == null ? '' : `:${row.dst_port}`}`;
}

function severityBadge(severity) {
  const value = String(severity || '').toLowerCase();
  const tone = ['critical', 'high'].includes(value) ? 'red' : value === 'medium' ? 'yellow' : value === 'low' ? 'green' : severityTone(value);
  return <Badge tone={tone}>{severity || 'unscored'}</Badge>;
}

function TableView({ rows, collection, investigationId, runId, hasMore, onLoadMore, loadingMore, onSelect, selectedId }) {
  const columns = {
    flows: [
      ['Protocol', (r) => r.protocol?.toUpperCase() || '—'],
      ['Source → destination', endpoint],
      ['Packets', (r) => formatNumber(r.packet_count, 0)],
      ['Bytes', (r) => formatBytes(r.byte_count)],
      ['First seen', (r) => stamp(r.first_seen)],
    ],
    sessions: [
      ['State', (r) => r.state],
      ['Endpoints', endpoint],
      ['Confidence', (r) => r.confidence],
      ['Reassembled', (r) => formatBytes(r.reassembled_bytes)],
      ['Quality', (r) => r.reassembly_quality == null ? '—' : `${formatNumber(r.reassembly_quality * 100, 1)}%`],
    ],
    artifacts: [
      ['Artifact type', (r) => r.artifact_type?.replaceAll('_', ' ') || '—'],
      ['Content type', (r) => r.content_type || '—'],
      ['Size', (r) => formatBytes(r.size_bytes)],
      ['SHA-256', (r) => r.sha256 || '—'],
      ['Captured', (r) => stamp(r.captured_at)],
    ],
    iocs: [
      ['Type', (r) => r.ioc_type],
      ['Indicator', (r) => r.ioc_value],
      ['Allowlist', (r) => r.is_allowlisted ? 'Allowlisted' : 'Not allowlisted'],
      ['Threat match', (r) => r.threat_intel_match && Object.keys(r.threat_intel_match).length ? 'Matched' : 'No match recorded'],
      ['Added', (r) => stamp(r.created_at)],
    ],
    cve_matches: [
      ['CVE', (r) => r.cve_id],
      ['Severity', (r) => r.severity],
      ['CVSS', (r) => r.cvss_score == null ? '—' : formatNumber(r.cvss_score, 1)],
      ['Match type', (r) => r.match_type],
      ['Confidence', (r) => r.confidence],
    ],
  }[collection] || [];

  if (!rows.length) return <Empty>No {collection.replace('_', ' ')} match the current filters.</Empty>;
  return (
    <>
      <div className="analysis-table-wrap">
        <table className="analysis-table">
          <thead><tr>{columns.map(([label]) => <th scope="col" key={label}>{label}</th>)}{collection === 'artifacts' && <th scope="col">File</th>}</tr></thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.id}
                className={selectedId === row.id ? 'selected' : ''}
                onClick={() => onSelect(row)}
                tabIndex={0}
                onKeyDown={(event) => { if (event.key === 'Enter' || event.key === ' ') { event.preventDefault(); onSelect(row); } }}
              >
                {columns.map(([label, render]) => <td key={label}>{render(row)}</td>)}
                {collection === 'artifacts' && <td>
                  {row.has_file ? (
                    <a className="analysis-download" href={api.investigationAnalysisArtifactDownloadUrl(investigationId, runId, row.id)} onClick={(event) => event.stopPropagation()} aria-label={`Download artifact ${row.id}`}><ArrowDownToLine size={13} />Download</a>
                  ) : <span className="analysis-muted">metadata only</span>}
                </td>}
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {hasMore && <button className="analysis-load-more" type="button" onClick={onLoadMore} disabled={loadingMore}>{loadingMore ? 'Loading…' : 'Load next page'}</button>}
    </>
  );
}

export default function InvestigationAnalysis({ investigation, refreshMs, onToast }) {
  const [selectedRunId, setSelectedRunId] = useState('');
  const [collection, setCollection] = useState('overview');
  const [searchText, setSearchText] = useState('');
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState('');
  const [extraPage, setExtraPage] = useState(null);
  const [selectedRecord, setSelectedRecord] = useState(null);
  const [triggering, setTriggering] = useState(false);
  const [confirmTrigger, setConfirmTrigger] = useState(false);
  const [loadingMore, setLoadingMore] = useState(false);

  const evidenceState = usePolling(
    () => api.getInvestigationEvidence(investigation.id),
    [investigation.id],
    refreshMs,
    Boolean(investigation.id),
  );
  const evidence = evidenceState.data?.items || [];
  const completeEvidence = useMemo(() => evidence.filter((item) => item.status === 'complete'), [evidenceState.data]);
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
  }, [investigation.id]);
  useEffect(() => {
    if (completeEvidence.length && !evidenceId) setEvidenceId(String(completeEvidence[0].file_id));
  }, [completeEvidence, evidenceId]);
  useEffect(() => {
    setExtraPage(null);
    setSelectedRecord(null);
  }, [investigation.id, selectedRunId, collection, query, filter]);

  const detailState = usePolling(
    () => selectedRun ? api.getInvestigationAnalysisDetail(investigation.id, selectedRun.run_id, false) : Promise.resolve(null),
    [investigation.id, selectedRun?.run_id],
    isActiveRun ? 5000 : 15000,
    Boolean(selectedRun),
  );
  const detail = detailState.data;
  const collectionParams = useMemo(() => {
    const params = { limit: 30, q: query };
    if (collection === 'flows' && filter) params.protocol = filter;
    if (collection === 'sessions' && filter) params.state = filter;
    if (collection === 'artifacts' && filter) params.artifact_type = filter;
    if (collection === 'iocs') {
      if (filter === 'allowlisted') params.is_allowlisted = true;
      if (filter === 'not_allowlisted') params.is_allowlisted = false;
      if (filter.startsWith('type:')) params.ioc_type = filter.slice(5);
    }
    if (collection === 'cve_matches' && filter) params.severity = filter;
    return params;
  }, [collection, query, filter]);
  const collectionState = usePolling(
    () => selectedRun && collection !== 'overview'
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

  async function triggerAnalysis() {
    const targetEvidence = Number(evidenceId || completeEvidence[0]?.file_id);
    if (!targetEvidence) return;
    setTriggering(true);
    try {
      const result = await api.triggerInvestigationAnalysis(investigation.id, targetEvidence);
      onToast(`PCAP analysis ${result.run_id} queued`);
      setConfirmTrigger(false);
      setSelectedRunId(result.run_id);
      setCollection('overview');
      runsState.refresh();
    } catch (error) {
      onToast(error.message, true);
    } finally {
      setTriggering(false);
    }
  }

  async function loadMore() {
    if (!nextCursor || !selectedRun || loadingMore) return;
    setLoadingMore(true);
    try {
      const result = await api.getInvestigationAnalysisCollection(
        investigation.id,
        selectedRun.run_id,
        collection,
        { ...collectionParams, cursor: nextCursor },
      );
      const previous = page?.items || [];
      setExtraPage({ key: collectionKey, data: { ...result, items: [...previous, ...result.items] } });
    } catch (error) {
      onToast(error.message, true);
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

  const severity = detail?.severity || selectedRun?.severity_score;
  const countFor = (item) => {
    if (!item.count) return null;
    if (selectedRun) return selectedRun[item.count] ?? 0;
    const detailKey = { flow_count: 'flows', session_count: 'sessions', artifact_count: 'artifacts', ioc_count: 'iocs', cve_match_count: 'cve_matches' }[item.count];
    return detail ? (detail.counts?.[detailKey] ?? 0) : null;
  };

  return (
    <section className="analysis-workspace" aria-label="PCAP analysis">
      <div className="analysis-workspace-head">
        <div>
          <div className="analysis-kicker">PACKET CAPTURE FORENSICS</div>
          <h3>Analysis results</h3>
          <p>Persisted results from analysis runs attached to this investigation.</p>
        </div>
        <div className="analysis-head-actions">
          {runs.length > 0 && <label className="analysis-run-picker"><span>RUN</span><select aria-label="Analysis run" value={selectedRun?.run_id || ''} onChange={(event) => setSelectedRunId(event.target.value)}>
            {runs.map((run) => <option key={run.run_id} value={run.run_id}>{run.run_id.slice(0, 12)} · {run.status} · {formatRelative(run.started_at)}</option>)}
          </select><ChevronDown size={13} aria-hidden="true" /></label>}
          {completeEvidence.length > 1 && <label className="analysis-evidence-picker"><span>CAPTURE</span><select aria-label="Capture to analyze" style={SELECT_STYLE} value={evidenceId} onChange={(event) => setEvidenceId(event.target.value)}><option value="">Choose capture</option>{completeEvidence.map((item) => <option key={item.file_id} value={item.file_id}>{item.filename || `Evidence #${item.file_id}`}</option>)}</select></label>}
          {CAN_WRITE && completeEvidence.length > 0 && <button className="analysis-trigger" type="button" onClick={() => setConfirmTrigger(true)} disabled={triggering || !evidenceId}>{triggering ? 'Queueing…' : 'Run analysis'}</button>}
        </div>
      </div>

      {(runsState.error || evidenceState.error || detailState.error || (collection !== 'overview' && collectionState.error)) && <ErrorLine>{runsState.error || evidenceState.error || detailState.error || collectionState.error}</ErrorLine>}

      {runsState.loading && !runsState.data ? <Empty><Spinner /> Loading analysis runs…</Empty> : runs.length === 0 ? (
        <div className="analysis-empty-state">
          <Workflow size={19} />
          <strong>No analysis run is attached to this investigation.</strong>
          <span>{completeEvidence.length ? 'Select a completed capture and run analysis to produce flows, sessions, indicators, and vulnerability matches.' : 'Analysis becomes available when a PCAP capture transfer completes.'}</span>
        </div>
      ) : (
        <>
          <div className="analysis-run-strip">
            {runs.slice(0, 5).map((run) => (
              <button type="button" key={run.run_id} className={`analysis-run-chip ${run.run_id === selectedRun?.run_id ? 'active' : ''}`} onClick={() => setSelectedRunId(run.run_id)}>
                <span className={`analysis-run-dot ${run.status}`} />
                <span className="analysis-run-name">{run.run_id.slice(0, 10)}</span>
                <Badge tone={statusTone(run.status)}>{run.status}</Badge>
                <time>{formatRelative(run.started_at)}</time>
              </button>
            ))}
            {runs.length > 5 && <span className="analysis-muted">Choose a run from the selector above.</span>}
          </div>

          {selectedRunId && !selectedRun && (
            <div className="analysis-progress-state"><span className="analysis-progress-spinner" /><div><strong>Waiting for the run record</strong><span>Submitted run {selectedRunId} has not appeared in the analysis index yet.</span></div></div>
          )}

          <div className="analysis-tabbar" role="tablist" aria-label="Analysis collections">
            {COLLECTIONS.map((item) => (
              <button type="button" role="tab" aria-selected={collection === item.key} key={item.key} className={collection === item.key ? 'active' : ''} onClick={() => selectCollection(item.key)}>
                {item.label}{item.count && <span>{formatNumber(countFor(item), 0)}</span>}
              </button>
            ))}
          </div>

          {!detail && detailState.loading ? <Empty><Spinner /> Loading selected run…</Empty> : null}
          {selectedRun && ['pending', 'running'].includes(selectedRun.status) && (
            <div className="analysis-progress-state"><span className="analysis-progress-spinner" /><div><strong>Analysis {selectedRun.status}</strong><span>{selectedRun.current_step ? `Current step: ${selectedRun.current_step.replaceAll('_', ' ')}` : 'Waiting for the analysis worker to report progress.'}</span></div><Badge tone={statusTone(selectedRun.status)}>{selectedRun.status}</Badge></div>
          )}
          {selectedRun && ['failed', 'rolled_back'].includes(selectedRun.status) && (
            <div className="analysis-failure-state"><ShieldAlert size={16} /><div><strong>Analysis {selectedRun.status.replace('_', ' ')}</strong><span>{selectedRun.error_message || selectedRun.error_step || 'The analysis worker did not return an error message.'}</span></div></div>
          )}

          {collection === 'overview' && selectedRun && (
            <div className="analysis-overview-content">
              <div className="analysis-overview-metrics">
                <div className="analysis-severity-card"><span>OVERALL SEVERITY</span><div>{severityBadge(severity?.overall_severity)}</div><strong>{severity?.overall_score == null ? '—' : formatNumber(severity.overall_score, 1)}</strong><small>Score reported by the analysis pipeline</small></div>
                <div className="analysis-overview-card"><span>CVSS BASE MAX</span><strong>{severity?.cvss_base_max == null ? '—' : formatNumber(severity.cvss_base_max, 1)}</strong><small>Highest matched CVSS score</small></div>
                <div className="analysis-overview-card"><span>IOC RISK SCORE</span><strong>{severity?.ioc_risk_score == null ? '—' : formatNumber(severity.ioc_risk_score, 1)}</strong><small>Calculated from extracted indicators</small></div>
                <div className="analysis-overview-card"><span>ANOMALY SCORE</span><strong>{severity?.anomaly_score == null ? '—' : formatNumber(severity.anomaly_score, 1)}</strong><small>Analysis result field</small></div>
              </div>
              <div className="analysis-run-metadata">
                <div><span>Evidence ID</span><strong>#{selectedRun.evidence_id}</strong></div>
                <div><span>Started</span><strong>{stamp(selectedRun.started_at)}</strong></div>
                <div><span>Completed</span><strong>{stamp(selectedRun.completed_at)}</strong></div>
                <div><span>Severity calculated</span><strong>{stamp(severity?.calculated_at)}</strong></div>
              </div>
              {detail?.severity?.factors && <details className="analysis-factors"><summary>Scoring factors returned by the backend</summary><pre>{JSON.stringify(detail.severity.factors, null, 2)}</pre></details>}
            </div>
          )}

          {collection !== 'overview' && selectedRun && (
            <div className="analysis-records">
              <div className="analysis-filter-row">
                <form className="analysis-search" onSubmit={submitSearch}><Search size={14} /><input aria-label={`Search ${collection.replace('_', ' ')}`} value={searchText} onChange={(event) => setSearchText(event.target.value)} placeholder={`Search ${collection.replace('_', ' ')}…`} /><button type="submit">Search</button></form>
                <label className="analysis-filter-label">FILTER
                  <select aria-label={`Filter ${collection.replace('_', ' ')}`} style={SELECT_STYLE} value={filter} onChange={(event) => setFilter(event.target.value)}>
                    <option value="">All records</option>
                    {collection === 'flows' && <><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option><option value="icmpv6">ICMPv6</option></>}
                    {collection === 'sessions' && <>{['established', 'open', 'closed', 'reset', 'half_open', 'incomplete'].map((value) => <option value={value} key={value}>{value.replace('_', ' ')}</option>)}</>}
                    {collection === 'artifacts' && ['http_request', 'http_response', 'dns_query', 'dns_response', 'tls_client_hello', 'tls_server_hello', 'tls_certificate', 'tls_ja3'].map((value) => <option value={value} key={value}>{value.replaceAll('_', ' ')}</option>)}
                    {collection === 'iocs' && <><option value="not_allowlisted">Not allowlisted</option><option value="allowlisted">Allowlisted</option>{['ipv4', 'ipv6', 'domain', 'url', 'sha256', 'ja3', 'port'].map((value) => <option value={`type:${value}`} key={value}>Type: {value}</option>)}</>}
                    {collection === 'cve_matches' && ['critical', 'high', 'medium', 'low', 'none'].map((value) => <option value={value} key={value}>{value}</option>)}
                  </select>
                </label>
                <span className="analysis-record-count">{formatNumber(collectionState.data?.total_count, 0)} records</span>
              </div>
              {collectionState.error ? <ErrorLine>{collectionState.error}</ErrorLine> : collectionState.loading && !collectionState.data ? <Empty><Spinner /> Loading {collection.replace('_', ' ')}…</Empty> : (
                <TableView rows={collectionItems} collection={collection} investigationId={investigation.id} runId={selectedRun.run_id} hasMore={hasMore} onLoadMore={loadMore} loadingMore={loadingMore} onSelect={setSelectedRecord} selectedId={selectedRecord?.id} />
              )}
              {selectedRecord && <div className="analysis-record-detail"><div><strong>Record #{selectedRecord.id}</strong><button type="button" onClick={() => setSelectedRecord(null)}>Close</button></div><pre>{JSON.stringify(selectedRecord, null, 2)}</pre></div>}
            </div>
          )}
        </>
      )}
      {confirmTrigger && (
        <div className="analysis-confirm-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget && !triggering) setConfirmTrigger(false); }}>
          <section className="analysis-confirm-dialog" role="dialog" aria-modal="true" aria-labelledby="analysis-confirm-title">
            <div className="analysis-kicker">PCAP PIPELINE</div>
            <h4 id="analysis-confirm-title">Queue packet analysis?</h4>
            <p>The selected completed capture will be submitted to the configured analysis pipeline. A new run will appear here as soon as it is created.</p>
            <div className="analysis-confirm-meta"><span>Investigation</span><strong>#{investigation.id}</strong><span>Evidence</span><strong>#{evidenceId || completeEvidence[0]?.file_id}</strong></div>
            <div className="analysis-confirm-actions"><button type="button" onClick={() => setConfirmTrigger(false)} disabled={triggering}>Cancel</button><button type="button" className="analysis-trigger" onClick={triggerAnalysis} disabled={triggering}>{triggering ? 'Queueing…' : 'Queue analysis'}</button></div>
          </section>
        </div>
      )}
    </section>
  );
}
