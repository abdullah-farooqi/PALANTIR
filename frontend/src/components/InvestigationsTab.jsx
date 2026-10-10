import { useEffect, useState } from 'react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { Badge, Box, Chips, DataTable, Empty, ErrorLine, Spinner } from './ui';
import NodeHeaderNav from './NodeHeaderNav';
import { CAN_WRITE } from '../lib/role';
import { describeTrigger, severityTone, statusTone } from '../lib/events';
import { formatDateTime, formatDuration, formatRelative, formatNumber, formatBytes, scoreToPercent } from '../lib/format';

function formatMetricValue(key, val) {
  if (val === null || val === undefined) return { label: key, value: '—' };

  // Memory in MB -> convert to bytes and format dynamically as GB or MB
  if (['ram_used_mb', 'ram_total_mb', 'swap_used_mb'].includes(key)) {
    const bytes = Number(val) * 1024 * 1024;
    const labelMap = {
      ram_used_mb: 'RAM Used',
      ram_total_mb: 'RAM Total',
      swap_used_mb: 'Swap Used',
    };
    return { label: labelMap[key] || key, value: formatBytes(bytes) };
  }

  // Percentage values
  if (key === 'cpu_pct') {
    return { label: 'CPU Usage', value: `${formatNumber(val, 1)}%` };
  }
  if (key === 'root_used_pct') {
    return { label: 'Root Disk Used', value: `${formatNumber(val, 1)}%` };
  }

  // System Load
  if (key === 'load_avg') {
    return { label: '1m Load', value: formatNumber(val, 2) };
  }

  // Clean labels for count keys
  const countLabels = {
    process_count: 'Processes',
    oom_kills: 'OOM Kills',
    sockets_count: 'Active Sockets',
    containers_total: 'Containers Total',
    containers_running: 'Containers Running',
    vms_total: 'VMs Total',
    vms_running: 'VMs Running',
    services_total: 'Services Total',
    active: 'Active Services',
    failed: 'Failed Services',
    filesystems: 'Filesystems',
    disk_devices: 'Disks',
    interfaces_count: 'Network Interfaces',
  };

  const label = countLabels[key] || key.replace(/_/g, ' ');
  return { label, value: typeof val === 'number' ? formatNumber(val, 0) : String(val) };
}

function Evidence({ inv }) {
  const out = inv.raw_output;
  if (!out || !out.evidence) return null;
  const ev = out.evidence;

  return (
    <div style={{ marginTop: 14 }}>
      {/* Assessment banner */}
      {out.assessment && (
        <div
          style={{
            background: 'rgba(57, 229, 105, 0.08)',
            border: '1px solid #1a4224',
            borderRadius: 6,
            padding: '8px 12px',
            color: '#a3c4aa',
            fontSize: 12,
            marginBottom: 12,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
          }}
        >
          <span style={{ color: '#39e569', fontWeight: 800 }}>ASSESSMENT:</span>
          <span style={{ color: '#fff', fontWeight: 700 }}>{out.assessment.result}</span>
          {out.assessment.root_cause_inferred === false && (
            <span style={{ color: '#728c78' }}>— telemetry evidence captured, no automated root cause inferred</span>
          )}
        </div>
      )}

      {/* Trigger info */}
      {out.trigger && out.trigger.type !== 'manual' && (
        <div
          style={{
            background: 'rgba(245, 158, 11, 0.08)',
            border: '1px solid #785215',
            borderRadius: 6,
            padding: '8px 12px',
            color: '#d8dee9',
            fontSize: 12,
            marginBottom: 14,
            display: 'flex',
            alignItems: 'center',
            gap: 8,
            flexWrap: 'wrap',
          }}
        >
          <span style={{ color: '#fbbf24', fontWeight: 800 }}>INCIDENT TRIGGER:</span>
          <span>{out.trigger.type} #{out.trigger.id}</span>
          {out.trigger.alert_name && (
            <>
              <b style={{ color: '#fff' }}>{out.trigger.alert_name}</b>
              <span style={{ color: '#728c78', fontFamily: 'JetBrains Mono, monospace' }}>{out.trigger.chart}</span>
            </>
          )}
          {out.trigger.severity && <Badge tone={severityTone(out.trigger.severity)}>{out.trigger.severity}</Badge>}
        </div>
      )}

      {/* Telemetry Evidence Grid */}
      <div style={{ fontSize: 12, fontWeight: 700, color: '#a3c4aa', letterSpacing: '0.04em', marginBottom: 8 }}>
        TELEMETRY EVIDENCE SNAPSHOT
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 14 }}>
        {(ev.latest_metrics || []).map((m, i) => {
          const metricEntries = Object.entries(m.metrics || {});
          return (
            <div
              key={i}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: 12,
                padding: '7px 12px',
                background: 'rgba(6, 12, 8, 0.5)',
                border: '1px solid #142e1a',
                borderRadius: 6,
                flexWrap: 'wrap',
                fontSize: 11.5,
              }}
            >
              <span
                style={{
                  color: '#22d3ee',
                  fontWeight: 700,
                  minWidth: 110,
                  textTransform: 'uppercase',
                  fontFamily: 'JetBrains Mono, monospace',
                }}
              >
                {m.category}
              </span>
              <div style={{ flex: 1, display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
                {metricEntries.length > 0 ? (
                  metricEntries.map(([k, v]) => {
                    const formatted = formatMetricValue(k, v);
                    return (
                      <span
                        key={k}
                        style={{
                          background: 'rgba(255, 255, 255, 0.03)',
                          border: '1px solid #17331e',
                          padding: '2px 8px',
                          borderRadius: 5,
                          fontSize: 11,
                          fontFamily: 'JetBrains Mono, monospace',
                        }}
                      >
                        <span style={{ color: '#8da693', marginRight: 4 }}>{formatted.label}:</span>
                        <span style={{ color: '#39e569', fontWeight: 700 }}>
                          {formatted.value}
                        </span>
                      </span>
                    );
                  })
                ) : (
                  <span style={{ color: '#6b7a6f' }}>—</span>
                )}
              </div>
            </div>
          );
        })}
      </div>

      {/* Active alerts during incident */}
      <div style={{ fontSize: 12, fontWeight: 700, color: '#a3c4aa', letterSpacing: '0.04em', marginBottom: 6 }}>
        CONCURRENT ACTIVE ALERTS ({(ev.active_alerts || []).length})
      </div>
      {(ev.active_alerts || []).length === 0 ? (
        <div style={{ color: '#728c78', fontSize: 11.5, marginBottom: 14 }}>No other active alerts recorded during incident window.</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, marginBottom: 14 }}>
          {(ev.active_alerts || []).map((a) => (
            <div key={a.id} className="row" style={{ gap: 8, fontSize: 12 }}>
              <Badge tone={severityTone(a.severity)}>{a.severity}</Badge>
              <b style={{ color: '#fff' }}>{a.alert_name}</b>
              <span style={{ color: '#728c78', fontFamily: 'JetBrains Mono, monospace' }}>{a.chart}</span>
            </div>
          ))}
        </div>
      )}

      {/* Recent anomalies */}
      <div style={{ fontSize: 12, fontWeight: 700, color: '#a3c4aa', letterSpacing: '0.04em', marginBottom: 6 }}>
        RECENT ANOMALOUS CONTEXTS ({(ev.recent_anomalies || []).length})
      </div>
      {(ev.recent_anomalies || []).length === 0 ? (
        <div style={{ color: '#728c78', fontSize: 11.5 }}>No recent anomaly events in evaluation baseline.</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
          {(ev.recent_anomalies || []).map((a) => (
            <div key={a.id} className="row" style={{ gap: 8, fontSize: 12 }}>
              <span style={{ color: '#94a3b8', fontFamily: 'JetBrains Mono, monospace' }}>{formatDateTime(a.detected_at)}</span>
              <Badge tone="purple">{Math.round(scoreToPercent(a.max_score))}%</Badge>
              <span style={{ color: '#d8dee9' }}>{(a.contexts || []).join(', ')}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function InvestigationsTab({ node, scope, setScope, refreshMs, focusId, onToast, onBack, onChangeView }) {
  const [status, setStatus] = useState('');
  const [selected, setSelected] = useState(null);
  const [creating, setCreating] = useState(false);

  const params = { node_id: scope === 'node' && node ? node.id : '', status, limit: 100 };
  const key = JSON.stringify(params);
  // Poll quickly while something is queued/running so progress feels live.
  const [fast, setFast] = useState(false);
  const state = usePolling(() => api.searchInvestigations(params), [key], fast ? Math.min(3000, refreshMs || 3000) : refreshMs, true);
  const items = state.data ? state.data.items : [];
  useEffect(() => { setFast(items.some((i) => i.status === 'queued' || i.status === 'running')); }, [items]);
  useEffect(() => { if (focusId) setSelected(focusId); }, [focusId]);
  useEffect(() => { if (!selected && items.length > 0) setSelected(items[0].id); }, [items, selected]);

  const current = items.find((i) => i.id === selected) || null;

  async function create() {
    if (!node) return;
    setCreating(true);
    try {
      const inv = await api.triggerInvestigation(node.id, 'manual');
      onToast(`investigation #${inv.id} queued`);
      setSelected(inv.id);
      state.refresh();
    } catch (err) {
      onToast(err.message, true);
    } finally {
      setCreating(false);
    }
  }

  const cols = [
    {
      key: 'id',
      label: 'ID',
      num: true,
      render: (r) => <span style={{ color: '#22d3ee', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>#{r.id}</span>,
    },
    { key: 'status', label: 'STATUS', render: (r) => <Badge tone={statusTone(r.status)}>{r.status}</Badge> },
    {
      key: 'trigger',
      label: 'TRIGGER',
      value: (r) => describeTrigger(r),
      render: (r) => (
        <span style={{ color: '#e2e8f0', fontWeight: 600 }}>
          {describeTrigger(r)}
        </span>
      ),
    },
    {
      key: 'progress',
      label: 'PROGRESS',
      num: true,
      render: (r) => (
        <span style={{ color: r.progress >= 100 ? '#39e569' : '#fbbf24', fontWeight: 700 }}>
          {r.progress}%
        </span>
      ),
    },
    {
      key: 'queued_at',
      label: 'QUEUED',
      render: (r) => (
        <span style={{ color: '#728c78', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
          {formatRelative(r.queued_at)}
        </span>
      ),
    },
  ];

  return (
    <>
      <NodeHeaderNav
        node={node}
        currentView="investigations"
        onViewChange={onChangeView}
        onBack={onBack}
      />

      <div className="two-col" style={{ alignItems: 'start' }}>
        {/* Left Box: Investigations List */}
        <Box
          n={5}
          title="INVESTIGATIONS"
          hot
          controls={
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
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
                value={status}
                onChange={(e) => setStatus(e.target.value)}
              >
                {['', 'queued', 'running', 'complete', 'failed'].map((s) => (
                  <option key={s} value={s}>
                    {s ? s.toUpperCase() : 'ANY STATUS'}
                  </option>
                ))}
              </select>
              <Chips
                value={scope}
                onChange={setScope}
                options={[
                  { value: 'node', label: 'THIS NODE' },
                  { value: 'fleet', label: 'FLEET' },
                ]}
              />
              {CAN_WRITE && (
                <button
                  className="btn sm primary"
                  onClick={create}
                  disabled={creating || !node}
                  style={{ padding: '3px 10px', fontSize: 11.5 }}
                >
                  {creating ? 'queuing…' : '+ Trigger Investigation'}
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
              {items.length} JOBS{fast ? ' • LIVE' : ''}
            </span>
          }
        >
          {state.error && <ErrorLine>{state.error}</ErrorLine>}
          {state.loading && !state.data ? (
            <Empty><Spinner /> loading jobs…</Empty>
          ) : (
            <div className="box-scroll" style={{ maxHeight: 'calc(100vh - 210px)' }}>
              <DataTable
                columns={cols}
                rows={items}
                rowKey={(r) => r.id}
                onRowClick={(r) => setSelected(r.id)}
                selectedKey={selected}
                initialSort={{ key: 'id', dir: 'desc' }}
                empty="No investigations yet. Alerts and anomalies trigger one automatically."
              />
            </div>
          )}
        </Box>

        {/* Right Box: Selected Job Details */}
        <Box
          n={null}
          title={current ? `INCIDENT INVESTIGATION #${current.id}` : 'JOB DETAILS'}
          right={current ? <Badge tone={statusTone(current.status)}>{current.status}</Badge> : ''}
        >
          {!current ? (
            <Empty>Select an investigation to view incident evidence.</Empty>
          ) : (
            <div className="box-scroll" style={{ maxHeight: 'calc(100vh - 210px)' }}>
              <div
                style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
                  gap: 10,
                  marginBottom: 12,
                  background: 'rgba(6, 12, 8, 0.6)',
                  border: '1px solid #142e1a',
                  borderRadius: 8,
                  padding: '12px 14px',
                }}
              >
                <div>
                  <div style={{ fontSize: 11, color: '#728c78', textTransform: 'uppercase' }}>TRIGGER</div>
                  <div style={{ color: '#fff', fontWeight: 700, fontSize: 13, marginTop: 2 }}>{describeTrigger(current)}</div>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: '#728c78', textTransform: 'uppercase' }}>JOB ID</div>
                  <div style={{ color: '#06b6d4', fontSize: 11.5, fontFamily: 'JetBrains Mono, monospace', marginTop: 2 }}>
                    {current.job_id ? current.job_id.slice(0, 16) + '…' : '—'}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: '#728c78', textTransform: 'uppercase' }}>QUEUED AT</div>
                  <div style={{ color: '#d8dee9', fontSize: 12, marginTop: 2 }}>{formatDateTime(current.queued_at)}</div>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: '#728c78', textTransform: 'uppercase' }}>COMPLETED AT</div>
                  <div style={{ color: '#d8dee9', fontSize: 12, marginTop: 2 }}>{formatDateTime(current.completed_at)}</div>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: '#728c78', textTransform: 'uppercase' }}>QUEUE DELAY</div>
                  <div style={{ color: '#39e569', fontWeight: 600, fontSize: 12, marginTop: 2 }}>
                    {current.queue_delay_ms === null || current.queue_delay_ms === undefined ? '—' : formatDuration(current.queue_delay_ms)}
                  </div>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: '#728c78', textTransform: 'uppercase' }}>PROGRESS</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2 }}>
                    <div className="pbar" style={{ width: 80 }}>
                      <i style={{ width: `${current.progress}%`, background: current.status === 'failed' ? 'var(--red)' : '#39e569' }} />
                    </div>
                    <span style={{ color: '#fff', fontWeight: 700, fontSize: 12 }}>{current.progress}%</span>
                  </div>
                </div>
              </div>

              {current.error_code && <ErrorLine>{current.error_code}: {current.error_message}</ErrorLine>}
              {current.summary && (
                <div style={{ fontSize: 12.5, color: '#e2e8f0', lineHeight: 1.5, margin: '8px 0' }}>
                  {current.summary}
                </div>
              )}
              <Evidence inv={current} />

              {current.raw_output && (
                <details style={{ marginTop: 14 }}>
                  <summary style={{ color: '#728c78', fontSize: 11.5, cursor: 'pointer', userSelect: 'none' }}>
                    ▸ View Raw JSON Evidence
                  </summary>
                  <pre className="pre" style={{ marginTop: 6, maxHeight: 250, fontSize: 11 }}>
                    {JSON.stringify(current.raw_output, null, 2)}
                  </pre>
                </details>
              )}
            </div>
          )}
        </Box>
      </div>
    </>
  );
}
