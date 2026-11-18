import { useEffect, useState } from 'react';
import { CheckCheck, Download, FileDown, Layers, Shield, Sliders } from 'lucide-react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { Badge, Box, Chips, Empty, ErrorLine, Spinner } from './ui';
import NodeHeaderNav from './NodeHeaderNav';
import RuleMatrixModal from './RuleMatrixModal';
import { CAN_WRITE } from '../lib/role';
import { severityTone } from '../lib/events';
import { formatAlertValue, formatDateTime, formatRelative, scoreToPercent } from '../lib/format';

function InvestigateBtn({ onInvestigate, type, id, existing }) {
  if (existing) {
    return (
      <button
        className="btn sm"
        onClick={() => onInvestigate(null, null, existing)}
        title="Open the linked investigation"
        style={{
          background: 'rgba(57, 229, 105, 0.12)',
          borderColor: '#2d6b3c',
          color: '#39e569',
          fontWeight: 700,
          borderRadius: 4,
          padding: '2px 8px',
        }}
      >
        inv #{existing}
      </button>
    );
  }
  if (!CAN_WRITE) return null;
  return (
    <button
      className="btn sm"
      onClick={() => onInvestigate(type, id)}
      style={{
        background: '#122216',
        borderColor: '#1f4327',
        color: '#a3c4aa',
        borderRadius: 4,
        padding: '2px 8px',
      }}
    >
      investigate
    </button>
  );
}

// ------------------------------------------------------------------ [1] active alerts (per node)
function ActiveAlerts({ state, onInvestigate, onPivot }) {
  const list = Array.isArray(state.data?.active)
    ? state.data.active
    : Array.isArray(state.data)
      ? state.data
      : [];
  const err = state.data && state.data.errors && state.data.errors.active;

  return (
    <Box
      n={1}
      title="ACTIVE ALERTS"
      hot
      right={
        <span
          style={{
            background: list.length > 0 ? 'rgba(239, 68, 68, 0.2)' : 'rgba(57, 229, 105, 0.12)',
            border: `1px solid ${list.length > 0 ? '#ef4444' : '#2d6b3c'}`,
            borderRadius: 5,
            padding: '2px 8px',
            color: list.length > 0 ? '#f87171' : '#39e569',
            fontWeight: 800,
            fontSize: 11,
            letterSpacing: '0.03em',
          }}
        >
          {list.length} {list.length === 1 ? 'ALERT FIRING' : 'ALERTS FIRING'}
        </span>
      }
    >
      {err && <ErrorLine>{err}</ErrorLine>}
      {list.length === 0 && !err ? (
        <div
          style={{
            background: 'rgba(6, 12, 8, 0.6)',
            border: '1px solid #142e1a',
            borderRadius: 8,
            padding: '14px 16px',
            color: '#728c78',
            fontSize: 12,
            display: 'flex',
            alignItems: 'center',
            gap: 10,
          }}
        >
          <span style={{ color: '#39e569', fontSize: 14 }}>✔</span>
          <span>No WARNING or CRITICAL alert is currently firing on this node.</span>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {list.map((a) => {
            const isCrit = (a.status || '').toUpperCase() === 'CRITICAL';
            return (
              <div
                key={a.id}
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: 12,
                  padding: '8px 12px',
                  background: isCrit ? 'rgba(239, 68, 68, 0.08)' : 'rgba(245, 158, 11, 0.08)',
                  border: `1px solid ${isCrit ? '#ef444444' : '#f59e0b44'}`,
                  borderRadius: 6,
                  flexWrap: 'wrap',
                }}
              >
                <Badge tone={severityTone(a.status)}>{a.status}</Badge>
                <b style={{ color: '#fff', fontSize: 12.5 }}>{a.alert_name}</b>
                <span style={{ color: '#728c78', fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5 }}>
                  {a.chart}
                </span>
                <span style={{ color: '#22d3ee', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
                  {formatAlertValue(a.value, a.units)}
                </span>
                <span className="grow" />
                <span style={{ color: '#728c78', fontSize: 11 }} title={formatDateTime(a.received_at)}>
                  {formatRelative(a.received_at)}
                </span>
                <InvestigateBtn onInvestigate={onInvestigate} type="alert" id={a.id} existing={a.investigation_id} />
              </div>
            );
          })}
        </div>
      )}
    </Box>
  );
}

// ------------------------------------------------------------------ [2] event feed (/events, cursor paged)
function EventFeed({ node, scope, setScope, onInvestigate, refreshMs, onPivot, onToast }) {
  const [type, setType] = useState('all');
  const [severity, setSeverity] = useState('');
  const [more, setMore] = useState([]);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState('');

  const [ruleMatrixOpen, setRuleMatrixOpen] = useState(false);
  const [selectedAlertIds, setSelectedAlertIds] = useState(new Set());
  const [acknowledging, setAcknowledging] = useState(false);
  const [exporting, setExporting] = useState(false);

  const params = {
    event_type: type,
    severity: type === 'anomaly' ? '' : severity,
    node_id: scope === 'node' && node ? node.id : '',
    limit: 100,
  };
  const key = JSON.stringify(params);
  const first = usePolling(() => api.getEvents(params), [key], refreshMs, true);
  useEffect(() => { setMore([]); setMoreError(''); setSelectedAlertIds(new Set()); }, [key]);

  const items = first.data ? first.data.items : [];
  const seen = new Set(items.map((e) => `${e.event_type}-${e.id}`));
  const all = items.concat(more.filter((e) => !seen.has(`${e.event_type}-${e.id}`)));
  const lastCursor = more.length > 0 ? more.cursor : first.data && first.data.next_cursor;
  const hasMore = more.length > 0 ? more.hasMore : first.data && first.data.has_more;

  async function loadMore() {
    setLoadingMore(true);
    setMoreError('');
    try {
      const page = await api.getEvents({ ...params, cursor: lastCursor });
      const merged = more.concat(page.items);
      merged.cursor = page.next_cursor;
      merged.hasMore = page.has_more;
      setMore(merged);
    } catch (err) {
      setMoreError(err.message);
    } finally {
      setLoadingMore(false);
    }
  }

  async function handleAcknowledgeSelected() {
    if (selectedAlertIds.size === 0) return;
    setAcknowledging(true);
    try {
      const ids = Array.from(selectedAlertIds);
      await api.acknowledgeEvents(ids);
      onToast?.(`Acknowledged ${ids.length} event(s)`);
      setSelectedAlertIds(new Set());
      first.refresh();
    } catch (err) {
      onToast?.(err.message || 'Failed to acknowledge events', true);
    } finally {
      setAcknowledging(false);
    }
  }

  async function handleExportEvents(format = 'stix') {
    setExporting(true);
    try {
      const res = await api.exportEvents(format);
      const blob = new Blob([JSON.stringify(res, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `palantir-events-${format}-${new Date().toISOString().slice(0, 10)}.json`;
      a.click();
      URL.revokeObjectURL(url);
      onToast?.(`Exported events feed as ${format.toUpperCase()}`);
    } catch (err) {
      onToast?.(err.message || 'Failed to export events', true);
    } finally {
      setExporting(false);
    }
  }

  return (
    <>
      <Box
        n={2}
        title="EVENTS & ANOMALY TIMELINE"
        controls={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <Chips
              value={type}
              onChange={setType}
              options={[
                { value: 'all', label: 'ALL' },
                { value: 'alert', label: 'ALERTS' },
                { value: 'anomaly', label: 'ANOMALIES' },
              ]}
            />
            {type !== 'anomaly' && (
              <select
                className="in"
                style={{
                  background: '#040805',
                  border: '1px solid #1a3821',
                  borderRadius: 6,
                  padding: '2px 8px',
                  fontSize: 11.5,
                  color: '#d8dee9',
                  outline: 'none',
                  fontFamily: 'JetBrains Mono, monospace',
                }}
                value={severity}
                onChange={(e) => setSeverity(e.target.value)}
              >
                <option value="">ANY SEVERITY</option>
                <option value="CRITICAL">CRITICAL</option>
                <option value="WARNING">WARNING</option>
                <option value="CLEAR">CLEAR</option>
              </select>
            )}
            <Chips
              value={scope}
              onChange={setScope}
              options={[...(node ? [{ value: 'node', label: 'THIS NODE' }] : []), { value: 'fleet', label: 'FLEET' }]}
            />

            <button
              type="button"
              className="btn sm"
              onClick={() => setRuleMatrixOpen(true)}
              style={{
                background: '#14171B',
                border: '1px solid #262B32',
                color: '#C6FF00',
                fontWeight: 700,
                borderRadius: 4,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
                fontSize: 11,
                padding: '2px 8px',
                cursor: 'pointer',
              }}
              title="Inspect active alert detection rules"
            >
              <Shield size={12} />
              <span>Rule Matrix (312)</span>
            </button>

            <button
              type="button"
              className="btn sm"
              onClick={() => handleExportEvents('stix')}
              disabled={exporting}
              style={{
                background: '#14171B',
                border: '1px solid #262B32',
                color: '#8B93A0',
                borderRadius: 4,
                display: 'inline-flex',
                alignItems: 'center',
                gap: 5,
                fontSize: 11,
                padding: '2px 8px',
                cursor: 'pointer',
              }}
              title="Export alerts feed as STIX 2.1 JSON bundle"
            >
              <FileDown size={12} />
              <span>{exporting ? 'Exporting…' : 'STIX 2.1'}</span>
            </button>

            {selectedAlertIds.size > 0 && CAN_WRITE && (
              <button
                type="button"
                className="btn sm primary"
                onClick={handleAcknowledgeSelected}
                disabled={acknowledging}
                style={{
                  background: '#C6FF00',
                  color: '#0A0B0D',
                  fontWeight: 800,
                  borderRadius: 4,
                  display: 'inline-flex',
                  alignItems: 'center',
                  gap: 5,
                  fontSize: 11,
                  padding: '2px 10px',
                  cursor: 'pointer',
                }}
              >
                <CheckCheck size={13} />
                <span>Acknowledge ({selectedAlertIds.size})</span>
              </button>
            )}
          </div>
        }
        right={
          <span
            style={{
              background: 'rgba(18, 38, 22, 0.8)',
              border: '1px solid #1c4524',
              borderRadius: 5,
              padding: '2px 8px',
              color: '#39e569',
              fontWeight: 700,
              fontSize: 11,
            }}
          >
            {all.length}{hasMore ? '+' : ''} EVENTS
          </span>
        }
      >
        {first.error && <ErrorLine>{first.error}</ErrorLine>}
        {first.loading && !first.data ? (
          <Empty><Spinner /> loading events…</Empty>
        ) : all.length === 0 ? (
          <div
            style={{
              background: 'rgba(6, 12, 8, 0.6)',
              border: '1px solid #142e1a',
              borderRadius: 8,
              padding: '16px 18px',
              color: '#728c78',
              fontSize: 12,
              lineHeight: 1.6,
            }}
          >
            <div style={{ color: '#a3c4aa', fontWeight: 700, marginBottom: 4 }}>
              No events match current filter.
            </div>
            <div>
              • <b>Alert events</b> are recorded when threshold triggers transition (WARNING / CRITICAL / CLEAR).<br />
              • <b>Anomaly records</b> are saved when the multi-context engine detects concurrent deviant metrics across evaluation cycles.
            </div>
          </div>
        ) : (
          <div
            className="box-scroll"
            style={{
              maxHeight: 'calc(100vh - 350px)',
              border: '1px solid #142e1a',
              borderRadius: 8,
              background: 'rgba(6, 12, 8, 0.6)',
              overflowY: 'auto',
              marginTop: 4,
            }}
          >
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 36, textAlign: 'center' }}>
                    <input
                      type="checkbox"
                      aria-label="Select all alerts"
                      checked={all.length > 0 && selectedAlertIds.size === all.length}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setSelectedAlertIds(new Set(all.map((x) => x.id)));
                        } else {
                          setSelectedAlertIds(new Set());
                        }
                      }}
                    />
                  </th>
                  <th>TIMESTAMP</th>
                  {scope === 'fleet' && <th>HOST</th>}
                  <th>TYPE</th>
                  <th>LEVEL / SCORE</th>
                  <th>INCIDENT CONTEXT & VALUE</th>
                  <th style={{ width: 100 }} />
                </tr>
              </thead>
              <tbody>
                {all.map((e) => (
                  <tr key={`${e.event_type}-${e.id}`}>
                    <td style={{ textAlign: 'center' }}>
                      <input
                        type="checkbox"
                        aria-label={`Select event ${e.id}`}
                        checked={selectedAlertIds.has(e.id)}
                        onChange={(ev) => {
                          ev.stopPropagation();
                          setSelectedAlertIds((prev) => {
                            const next = new Set(prev);
                            if (next.has(e.id)) next.delete(e.id);
                            else next.add(e.id);
                            return next;
                          });
                        }}
                      />
                    </td>
                    <td style={{ color: '#94a3b8', fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5 }} title={formatRelative(e.occurred_at)}>
                      {formatDateTime(e.occurred_at)}
                    </td>
                    {scope === 'fleet' && (
                      <td
                        style={{
                          color: '#39e569',
                          fontWeight: 700,
                          cursor: onPivot ? 'pointer' : 'default',
                          textDecoration: onPivot ? 'underline' : 'none',
                          textUnderlineOffset: '3px',
                        }}
                        onClick={() => onPivot && onPivot(e.hostname, 'Domain')}
                        title={onPivot ? 'Correlate in Pivot Forensic Drawer' : undefined}
                      >
                        {e.hostname}
                      </td>
                    )}
                    <td>
                      <span
                        style={{
                          color: e.event_type === 'alert' ? '#fbbf24' : '#c084fc',
                          fontWeight: 700,
                          fontSize: 11,
                          textTransform: 'uppercase',
                        }}
                      >
                        {e.event_type}
                      </span>
                    </td>
                    <td>
                      {e.event_type === 'alert' ? (
                        <Badge tone={severityTone(e.severity)}>{e.severity}</Badge>
                      ) : (
                        <Badge tone="purple">{Math.round(scoreToPercent(e.max_score) || 0)}%</Badge>
                      )}
                    </td>
                    <td style={{ maxWidth: 560 }}>
                      {e.event_type === 'alert' ? (
                        <>
                          <b style={{ color: '#fff' }}>{e.alert_name}</b>{' '}
                          <span style={{ color: '#728c78', fontFamily: 'JetBrains Mono, monospace' }}>{e.chart}</span>{' '}
                          <span style={{ color: '#22d3ee', fontWeight: 700 }}>{formatAlertValue(e.value, e.units)}</span>
                        </>
                      ) : (
                        <span title={JSON.stringify(e.scores)} style={{ color: '#cbd5e1' }}>
                          {(e.contexts || []).slice(0, 4).map((c) => `${c} ${e.scores && e.scores[c] !== undefined ? `(${Math.round(scoreToPercent(e.scores[c]))}%)` : ''}`).join(' · ')}
                          {(e.contexts || []).length > 4 ? ` +${e.contexts.length - 4}` : ''}
                        </span>
                      )}
                    </td>
                    <td>
                      {(e.event_type === 'anomaly' || e.severity === 'WARNING' || e.severity === 'CRITICAL') && (
                        <InvestigateBtn
                          onInvestigate={(t, id, existing) => onInvestigate(t, id, existing, e.node_id)}
                          type={e.event_type}
                          id={e.id}
                          existing={e.investigation_id}
                        />
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
            {moreError && <ErrorLine>{moreError}</ErrorLine>}
            {hasMore && (
              <div style={{ padding: '8px 12px', borderTop: '1px solid #142e1a' }}>
                <button
                  className="btn primary sm"
                  onClick={loadMore}
                  disabled={loadingMore}
                  style={{ padding: '4px 12px' }}
                >
                  {loadingMore ? 'loading older events…' : 'Load Older Events'}
                </button>
              </div>
            )}
          </div>
        )}
      </Box>

      <RuleMatrixModal
        isOpen={ruleMatrixOpen}
        onClose={() => setRuleMatrixOpen(false)}
        onToast={onToast}
      />
    </>
  );
}

export default function AlertsTab({ node, state, scope, setScope, onInvestigate, refreshMs, onBack, onChangeView, onPivot, onToast }) {
  return (
    <>
      {scope === 'node' && node && <NodeHeaderNav node={node} currentView="events" onViewChange={onChangeView} onBack={onBack} />}

      <div style={{ display: 'grid', gap: 14 }}>
        {scope === 'node' && node && <ActiveAlerts state={state} onInvestigate={onInvestigate} onPivot={onPivot} />}
        <EventFeed node={node} scope={scope} setScope={setScope} onInvestigate={onInvestigate} refreshMs={refreshMs} onPivot={onPivot} onToast={onToast} />
      </div>
    </>
  );
}
