import { useEffect, useState } from 'react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { Badge, Box, Chips, DataTable, Empty, ErrorLine, Spinner } from './ui';
import { CAN_WRITE } from '../lib/role';
import { describeTrigger, severityTone, statusTone } from '../lib/events';
import { formatDateTime, formatDuration, formatRelative, formatNumber, scoreToPercent } from '../lib/format';

function Evidence({ inv }) {
  const out = inv.raw_output;
  if (!out || !out.evidence) return null;
  const ev = out.evidence;
  return (
    <div style={{ marginTop: 8 }}>
      {out.assessment && (
        <div className="tone-dim">assessment: {out.assessment.result}{out.assessment.root_cause_inferred === false ? ' — evidence only, no root cause inferred' : ''}</div>
      )}
      {out.trigger && out.trigger.type !== 'manual' && (
        <div style={{ marginTop: 6 }}>
          trigger: {out.trigger.type} #{out.trigger.id}{' '}
          {out.trigger.alert_name && <><b>{out.trigger.alert_name}</b> <span className="tone-dim">{out.trigger.chart}</span></>}
          {out.trigger.severity && <Badge tone={severityTone(out.trigger.severity)}>{out.trigger.severity}</Badge>}
        </div>
      )}
      <div className="tone-dim" style={{ marginTop: 8 }}>latest metrics</div>
      {(ev.latest_metrics || []).map((m, i) => (
        <div key={i} className="row" style={{ flexWrap: 'wrap', gap: 10 }}>
          <span className="tone-cyan" style={{ minWidth: 90 }}>{m.category}</span>
          <span className="tone-dim" style={{ minWidth: 100 }}>{m.source}</span>
          <span>{Object.entries(m.metrics || {}).map(([k, v]) => `${k}=${formatNumber(v, 2)}`).join('  ') || '—'}</span>
        </div>
      ))}
      <div className="tone-dim" style={{ marginTop: 8 }}>active alerts ({(ev.active_alerts || []).length})</div>
      {(ev.active_alerts || []).map((a) => (
        <div key={a.id} className="row"><Badge tone={severityTone(a.severity)}>{a.severity}</Badge><b>{a.alert_name}</b><span className="tone-dim">{a.chart}</span></div>
      ))}
      <div className="tone-dim" style={{ marginTop: 8 }}>recent anomalies ({(ev.recent_anomalies || []).length})</div>
      {(ev.recent_anomalies || []).map((a) => (
        <div key={a.id}>{formatDateTime(a.detected_at)} <Badge tone="purple">{Math.round(scoreToPercent(a.max_score))}%</Badge> <span className="tone-dim">{(a.contexts || []).join(', ')}</span></div>
      ))}
    </div>
  );
}

export default function InvestigationsTab({ node, scope, setScope, refreshMs, focusId, onToast }) {
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
    { key: 'id', label: 'ID', num: true },
    { key: 'status', label: 'Status', render: (r) => <Badge tone={statusTone(r.status)}>{r.status}</Badge> },
    { key: 'trigger', label: 'Trigger', value: (r) => describeTrigger(r), render: (r) => describeTrigger(r) },
    { key: 'progress', label: 'Prog', num: true, render: (r) => `${r.progress}%` },
    { key: 'queued_at', label: 'Queued', render: (r) => <span className="tone-dim">{formatRelative(r.queued_at)}</span> },
  ];

  return (
    <div className="two-col" style={{ marginTop: 6, alignItems: 'start' }}>
      <Box
        n={5}
        title="investigations"
        hot
        controls={
          <>
            <select className="in" style={{ marginLeft: 4 }} value={status} onChange={(e) => setStatus(e.target.value)}>
              {['', 'queued', 'running', 'complete', 'failed'].map((s) => <option key={s} value={s}>{s || 'any status'}</option>)}
            </select>
            <Chips value={scope} onChange={setScope} options={[{ value: 'node', label: 'this node' }, { value: 'fleet', label: 'fleet' }]} />
            {CAN_WRITE && <button className="btn sm primary" style={{ marginLeft: 6 }} onClick={create} disabled={creating || !node}>{creating ? 'queuing…' : '+ investigate node'}</button>}
          </>
        }
        right={`${items.length} jobs${fast ? ' • live' : ''}`}
      >
        {state.error && <ErrorLine>{state.error}</ErrorLine>}
        {state.loading && !state.data ? <Empty><Spinner /> loading…</Empty> : (
          <div className="box-scroll" style={{ maxHeight: 'calc(100vh - 190px)' }}>
            <DataTable columns={cols} rows={items} rowKey={(r) => r.id} onRowClick={(r) => setSelected(r.id)} selectedKey={selected} initialSort={{ key: 'id', dir: 'desc' }} empty="No investigations yet. WARNING/CRITICAL alerts and qualifying anomalies queue one automatically." />
          </div>
        )}
      </Box>

      <Box n={null} title={current ? `investigation #${current.id}` : 'details'} right={current ? <Badge tone={statusTone(current.status)}>{current.status}</Badge> : ''}>
        {!current ? <Empty>Select an investigation.</Empty> : (
          <div className="box-scroll" style={{ maxHeight: 'calc(100vh - 190px)' }}>
            <div className="kv">
              <span className="k">trigger</span><span /><span className="v">{describeTrigger(current)}</span>
              <span className="k">job id</span><span /><span className="v tone-dim">{current.job_id || '—'}</span>
              <span className="k">queued</span><span /><span className="v">{formatDateTime(current.queued_at)}</span>
              <span className="k">started</span><span /><span className="v">{formatDateTime(current.started_at)}</span>
              <span className="k">completed</span><span /><span className="v">{formatDateTime(current.completed_at)}</span>
              <span className="k">queue delay</span><span /><span className="v">{current.queue_delay_ms === null || current.queue_delay_ms === undefined ? '—' : formatDuration(current.queue_delay_ms)}</span>
              <span className="k">progress</span>
              <div className="pbar"><i style={{ width: `${current.progress}%`, background: current.status === 'failed' ? 'var(--red)' : undefined }} /></div>
              <span className="v">{current.progress}%</span>
            </div>
            {current.error_code && <ErrorLine>{current.error_code}: {current.error_message}</ErrorLine>}
            {current.summary && <div style={{ marginTop: 8 }}>{current.summary}</div>}
            <Evidence inv={current} />
            {current.raw_output && (
              <details style={{ marginTop: 8 }}>
                <summary className="tone-dim" style={{ cursor: 'pointer' }}>raw result JSON</summary>
                <pre className="pre">{JSON.stringify(current.raw_output, null, 2)}</pre>
              </details>
            )}
          </div>
        )}
      </Box>
    </div>
  );
}
