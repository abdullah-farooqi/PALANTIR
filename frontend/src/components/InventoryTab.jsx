import { useMemo, useState } from 'react';
import { Badge, Box, Chips, DataTable, Empty, ErrorLine, Meter } from './ui';
import { agentStatus, containerSources, listOf, storageSummary, vmSources } from '../lib/metrics';
import { formatBytes, formatNumber, formatPercent, formatCount } from '../lib/format';

const SECTIONS = [
  { value: 'services', label: 'services', hotkey: 's' },
  { value: 'containers', label: 'containers', hotkey: 'c' },
  { value: 'vms', label: 'vms', hotkey: 'v' },
  { value: 'sockets', label: 'sockets', hotkey: 'k' },
  { value: 'storage', label: 'storage', hotkey: 'd' },
  { value: 'caps', label: 'capabilities', hotkey: 'p' },
];

function SourceBadges({ sources }) {
  const entries = Object.entries(sources || {});
  if (entries.length === 0) return null;
  return (
    <div className="row" style={{ gap: 6, flexWrap: 'wrap', marginBottom: 6 }}>
      {entries.map(([name, s]) => {
        const status = (s && s.status) || 'unknown';
        const tone = status === 'available' ? 'green' : status === 'not_configured' ? 'dim' : 'yellow';
        return (
          <Badge key={name} tone={tone} title={s && s.reason ? s.reason : status}>
            {name}: {status.replace('_', ' ')}{s && s.count !== undefined ? ` (${s.count})` : ''}
          </Badge>
        );
      })}
    </div>
  );
}

const stateTone = (v) => {
  const s = String(v || '').toLowerCase();
  if (['active', 'running', 'listen', 'established', 'up'].includes(s)) return 'tone-green';
  if (['failed', 'dead', 'error', 'crashed'].includes(s)) return 'tone-red';
  if (['exited', 'inactive', 'stopped', 'shut off', 'paused'].includes(s)) return 'tone-dim';
  return '';
};

function Services({ latest, filter }) {
  const rows = listOf(latest, 'services', 'services');
  const failed = rows.filter((r) => r.active === 'failed').length;
  const active = rows.filter((r) => r.active === 'active').length;
  const cols = [
    { key: 'unit', label: 'Unit' },
    { key: 'active', label: 'Active', value: (r) => (r.active === 'failed' ? 0 : r.active === 'active' ? 1 : 2), render: (r) => <span className={stateTone(r.active)}>{r.active}</span> },
    { key: 'sub', label: 'Sub', render: (r) => <span className={stateTone(r.sub)}>{r.sub}</span> },
    { key: 'load', label: 'Load' },
    { key: 'description', label: 'Description' },
  ];
  return (
    <>
      <div className="tone-dim" style={{ marginBottom: 6 }}>
        {rows.length} units • <span className="tone-green">{active} active</span> • <span className={failed ? 'tone-red' : ''}>{failed} failed</span>
      </div>
      <DataTable columns={cols} rows={rows} rowKey={(r) => r.unit} filter={filter} initialSort={{ key: 'active', dir: 'asc' }} empty={emptyMsg(latest, 'services', 'systemd services (the collector needs the host D-Bus socket mounted)')} />
    </>
  );
}

function Containers({ latest, filter }) {
  const rows = listOf(latest, 'containers', 'containers').map((c) => ({
    ...c,
    cpu: c.metrics && typeof c.metrics.cpu_percent === 'number' ? c.metrics.cpu_percent : null,
    mem: c.metrics && typeof c.metrics.memory_usage_bytes === 'number' ? c.metrics.memory_usage_bytes : null,
    memLimit: c.metrics && typeof c.metrics.memory_limit_bytes === 'number' ? c.metrics.memory_limit_bytes : null,
  }));
  const cols = [
    { key: 'name', label: 'Name' },
    { key: 'runtime', label: 'Runtime' },
    { key: 'image', label: 'Image' },
    { key: 'state', label: 'State', render: (r) => <span className={stateTone(r.state || r.status)}>{r.state || r.status || '—'}</span> },
    { key: 'cpu', label: 'Cpu%', num: true, render: (r) => (r.cpu === null ? '—' : formatNumber(r.cpu, 1)) },
    { key: 'mem', label: 'Mem', num: true, render: (r) => (r.mem === null ? '—' : formatBytes(r.mem)) },
    { key: 'status', label: 'Status' },
  ];
  return (
    <>
      <SourceBadges sources={containerSources(latest)} />
      <DataTable columns={cols} rows={rows} rowKey={(r, i) => `${r.runtime}-${r.id || r.name}-${i}`} filter={filter} initialSort={{ key: 'state', dir: 'desc' }} empty={emptyMsg(latest, 'containers', 'containers')} />
    </>
  );
}

function Vms({ latest, filter }) {
  const rows = listOf(latest, 'vms', 'vms');
  const cols = [
    { key: 'name', label: 'Name' },
    { key: 'state', label: 'State', render: (r) => <span className={stateTone(r.state || r.status)}>{r.state || r.status || '—'}</span> },
    { key: 'cpu_count', label: 'vCPU', num: true },
    { key: 'max_memory', label: 'Max mem' },
    { key: 'used_memory', label: 'Used mem' },
  ];
  return (
    <>
      <SourceBadges sources={vmSources(latest)} />
      <DataTable columns={cols} rows={rows} rowKey={(r, i) => `${r.name}-${i}`} filter={filter} empty={emptyMsg(latest, 'vms', 'virtual machines (libvirt / Proxmox not reachable from the collector)')} />
    </>
  );
}

function Sockets({ latest, filter }) {
  const rows = listOf(latest, 'connections', 'sockets').map((s) => ({
    ...s,
    local: `${s.local_address}:${s.local_port}`,
    remote: s.remote_address ? `${s.remote_address}:${s.remote_port}` : '*',
  }));
  const by = useMemo(() => {
    const m = {};
    rows.forEach((r) => { m[r.state || r.type] = (m[r.state || r.type] || 0) + 1; });
    return Object.entries(m).sort((a, b) => b[1] - a[1]);
  }, [rows]);
  const cols = [
    { key: 'type', label: 'Proto' },
    { key: 'local', label: 'Local' },
    { key: 'remote', label: 'Remote' },
    { key: 'state', label: 'State', render: (r) => <span className={stateTone(r.state)}>{r.state || '—'}</span> },
    { key: 'pid', label: 'Pid', num: true },
    { key: 'process', label: 'Process' },
  ];
  const truncated = (latest && listOf(latest, 'connections', 'sockets').length >= 5000);
  return (
    <>
      <div className="tone-dim" style={{ marginBottom: 6 }}>
        {formatCount(rows.length)} sockets{truncated ? ' (truncated at 5000)' : ''} — {by.map(([k, v]) => `${k}: ${v}`).join(' • ')}
      </div>
      <DataTable columns={cols} rows={rows} rowKey={(r, i) => `${r.pid}-${r.local}-${r.remote}-${i}`} filter={filter} initialSort={{ key: 'state', dir: 'asc' }} empty={emptyMsg(latest, 'connections', 'sockets')} />
    </>
  );
}

function Storage({ latest, filter }) {
  const st = useMemo(() => storageSummary(latest), [latest]);
  const fsCols = [
    { key: 'mount', label: 'Mount' },
    { key: 'device', label: 'Device' },
    { key: 'fs', label: 'FS' },
    { key: 'total', label: 'Total', num: true, render: (r) => formatBytes(r.total) },
    { key: 'used', label: 'Used', num: true, render: (r) => formatBytes(r.used) },
    { key: 'free', label: 'Free', num: true, render: (r) => formatBytes(r.free) },
    {
      key: 'pct', label: 'Use%', num: true,
      render: (r) => (r.pct === null ? <span className="tone-dim">{r.status}</span> : (
        <span className="row" style={{ gap: 6, justifyContent: 'flex-end' }}><span style={{ width: 80, display: 'inline-flex' }}><Meter pct={r.pct} /></span>{formatPercent(r.pct, 0)}</span>
      )),
    },
  ];
  const ioCols = [
    { key: 'device', label: 'Device' },
    { key: 'read_bytes', label: 'Read', num: true, render: (r) => formatBytes(r.read_bytes) },
    { key: 'write_bytes', label: 'Written', num: true, render: (r) => formatBytes(r.write_bytes) },
    { key: 'read_count', label: 'Reads', num: true, render: (r) => formatCount(r.read_count) },
    { key: 'write_count', label: 'Writes', num: true, render: (r) => formatCount(r.write_count) },
  ];
  if (!st.available) return <Empty>{emptyMsg(latest, 'storage', 'storage data')}</Empty>;
  return (
    <>
      <DataTable columns={fsCols} rows={st.filesystems} rowKey={(r) => r.mount + r.device} filter={filter} />
      <div className="tone-dim" style={{ margin: '10px 0 4px' }}>disk I/O (cumulative since boot)</div>
      <DataTable columns={ioCols} rows={st.diskIo} rowKey={(r) => r.device} filter={filter} initialSort={{ key: 'device', dir: 'asc' }} empty="no disk counters" />
      {st.raid && (
        <div style={{ marginTop: 10 }}>
          <div className="tone-dim">software RAID: {st.raid.detected ? `${(st.raid.arrays || []).length} array(s) detected` : 'none detected'}</div>
          {st.raid.detected && <pre className="pre">{st.raid.mdstat_raw}</pre>}
        </div>
      )}
    </>
  );
}

function emptyMsg(latest, cat, what) {
  const status = agentStatus(latest, cat);
  if (status === null) return `No ${what} yet. The host collector has not reported this category.`;
  if (status === 'unavailable' || status === 'permission_denied') return `The collector reports ${what} as ${status.replace('_', ' ')} on this host.`;
  return `No ${what} reported.`;
}

export default function InventoryTab({ node, state, section, setSection }) {
  const [filter, setFilter] = useState('');
  const latest = state.data && state.data.latest;
  if (state.loading && !state.data) return <Empty><span className="spinner" /> loading…</Empty>;
  if (!state.data) return <ErrorLine>{state.error || 'No data'}</ErrorLine>;
  if (!latest) return <ErrorLine>{(state.data.errors && state.data.errors.latest) || 'No telemetry returned'}</ErrorLine>;
  const caps = (node && node.capabilities) || {};

  return (
    <Box
      n={2}
      title="inventory"
      hot
      controls={
        <>
          <Chips value={section} onChange={setSection} options={SECTIONS} />
          {section !== 'caps' && <input className="in" style={{ width: 150, marginLeft: 6 }} placeholder="filter…" value={filter} onChange={(e) => setFilter(e.target.value)} />}
        </>
      }
      right={node ? node.hostname : ''}
    >
      <div className="box-scroll" style={{ maxHeight: 'calc(100vh - 190px)' }}>
        {section === 'services' && <Services latest={latest} filter={filter} />}
        {section === 'containers' && <Containers latest={latest} filter={filter} />}
        {section === 'vms' && <Vms latest={latest} filter={filter} />}
        {section === 'sockets' && <Sockets latest={latest} filter={filter} />}
        {section === 'storage' && <Storage latest={latest} filter={filter} />}
        {section === 'caps' && (
          Object.keys(caps).length === 0 ? (
            <Empty>No collector capabilities stored for this node (no collector_url, or it has not answered yet).</Empty>
          ) : (
            <pre className="pre">{JSON.stringify(caps, null, 2)}</pre>
          )
        )}
      </div>
    </Box>
  );
}

export { SECTIONS as INVENTORY_SECTIONS };
