import { useEffect, useState } from 'react';
import { Dot, Spinner } from './ui';
import { CAN_WRITE, UI_ROLE } from '../lib/role';
import { formatClock, formatRelative } from '../lib/format';
import { statusTone } from '../lib/events';

export const VIEWS = [
  { key: 'fleet', label: 'hosts grid', hotkey: '1' },
  { key: 'overview', label: 'overview', hotkey: '2' },
  { key: 'inventory', label: 'inventory', hotkey: '3' },
  { key: 'events', label: 'events', hotkey: '4' },
  { key: 'logs', label: 'logs', hotkey: '5' },
  { key: 'investigations', label: 'investigations', hotkey: '6' },
];

export const REFRESH_OPTIONS = [
  { value: 5000, label: '5s' },
  { value: 10000, label: '10s' },
  { value: 30000, label: '30s' },
  { value: 0, label: 'off' },
];

function Clock() {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  return <span className="tone-fg">{formatClock(now)}</span>;
}

function pipelineTone(ops, summary) {
  if (ops) return ops.status === 'healthy' ? 'green' : 'red';
  if (summary) {
    const w = Object.values((summary.health && summary.health.workers) || {});
    if (w.some((x) => x.status === 'stale' || x.status === 'failed')) return 'red';
    if (w.every((x) => x.status === 'healthy' || x.status === 'running')) return 'green';
  }
  return 'dim';
}

function pipelineTitle(ops, summary) {
  const lines = [];
  if (ops) {
    lines.push(`overall: ${ops.status}`, `database: ${ops.database.status}`, `redis: ${ops.redis.status}`);
    lines.push(`celery workers: ${ops.celery.workers.status} (${ops.celery.workers.workers.length})`, `beat: ${ops.celery.beat_dispatch.status}`);
    if (ops.celery.queue_depth !== null && ops.celery.queue_depth !== undefined) lines.push(`queue depth: ${ops.celery.queue_depth}`);
    Object.entries(ops.tasks || {}).forEach(([k, v]) => lines.push(`${k}: ${v.status}`));
  } else if (summary) {
    Object.entries((summary.health && summary.health.workers) || {}).forEach(([k, v]) => lines.push(`${k}: ${v.status}`));
  }
  return lines.join('\n') || 'no health data';
}

export function TopBar({ view, setView, fleet, refreshMs, setRefreshMs, refreshing, onRefresh }) {
  return (
    <header className="topbar flex-col-topbar">
      <div className="topbar-main-row">
        <div className="brand-group" onClick={() => setView('fleet')} title="Return to Fleet Grid">
          <span className="brand">PALANTIR</span>
        </div>

        <div className="topbar-right-group">
          <div className="topbar-clock-box">
            <Clock />
          </div>
          
          <button
            className={`user-menu-btn ${view === 'settings' ? 'admin-active' : ''}`}
            onClick={() => setView(view === 'settings' ? 'fleet' : 'settings')}
            title="Open System Settings"
          >
            <svg className="menu-icon-svg" viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <circle cx="12" cy="12" r="3"/>
              <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/>
            </svg>
            <span className="menu-btn-role">Settings</span>
          </button>
        </div>
      </div>
    </header>
  );
}

export function NodeBar({ nodes, selectedId, onSelect, onAdd, onRemove, onViewGrid, currentView }) {
  return (
    <div className="nodebar">
      <button className={`btn sm ${currentView === 'fleet' ? 'primary' : ''}`} onClick={onViewGrid} title="View all target hosts grid">
        ⊞ Hosts Grid
      </button>
      <span className="sep">│</span>
      <span className="tone-dim">active node:</span>
      {nodes.length === 0 && <span className="tone-dim">none registered yet</span>}
      {nodes.map((n) => (
        <button key={n.id} className={`nodetab ${n.id === selectedId && currentView !== 'fleet' ? 'on' : ''}`} onClick={() => onSelect(n.id)} title={`${n.collector_url || n.netdata_url}\nlast contact ${formatRelative(n.last_seen_at)}`}>
          <Dot tone={statusTone(n.reachability)} />
          {n.hostname}
        </button>
      ))}
      <span className="grow" />
      {CAN_WRITE && (
        <>
          <button className="btn sm" onClick={onAdd}><span className="kbd">a</span> add node</button>
          {selectedId && currentView !== 'fleet' && <button className="btn sm danger" onClick={onRemove}>deactivate</button>}
        </>
      )}
    </div>
  );
}
