import { useMemo, useState } from 'react';
import { Badge, Box, Chips, DataTable, Empty, ErrorLine, Meter } from './ui';
import NodeHeaderNav from './NodeHeaderNav';
import { agentStatus, containerSources, listOf, storageSummary, vmSources } from '../lib/metrics';
import { formatBytes, formatNumber, formatPercent, formatCount } from '../lib/format';

const SECTIONS = [
  { value: 'services', label: 'SERVICES', hotkey: 's' },
  { value: 'containers', label: 'CONTAINERS', hotkey: 'c' },
  { value: 'vms', label: 'VIRTUAL MACHINES', hotkey: 'v' },
  { value: 'sockets', label: 'NETWORK SOCKETS', hotkey: 'k' },
  { value: 'storage', label: 'STORAGE & I/O', hotkey: 'd' },
  { value: 'caps', label: 'CAPABILITIES', hotkey: 'p' },
];

function SourceBadges({ sources }) {
  const entries = Object.entries(sources || {});
  if (entries.length === 0) return null;
  return (
    <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 12 }}>
      {entries.map(([name, s]) => {
        const status = (s && s.status) || 'unknown';
        const isAvail = status === 'available';
        const isDim = status === 'not_configured';
        const bg = isAvail ? 'rgba(57, 229, 105, 0.12)' : isDim ? 'rgba(255, 255, 255, 0.05)' : 'rgba(250, 204, 21, 0.12)';
        const border = isAvail ? '#2d6b3c' : isDim ? '#1f3324' : '#8c6d32';
        const color = isAvail ? '#39e569' : isDim ? '#728c78' : '#facc15';

        return (
          <span
            key={name}
            title={s && s.reason ? s.reason : status}
            style={{
              background: bg,
              border: `1px solid ${border}`,
              color,
              padding: '2px 8px',
              borderRadius: 5,
              fontSize: 11,
              fontWeight: 700,
              fontFamily: 'JetBrains Mono, monospace',
              letterSpacing: '0.02em',
            }}
          >
            {name}: {status.replace('_', ' ')}{s && s.count !== undefined ? ` (${s.count})` : ''}
          </span>
        );
      })}
    </div>
  );
}

const renderStateBadge = (val) => {
  const s = String(val || '').toLowerCase();
  if (['active', 'running', 'listen', 'established', 'up'].includes(s)) {
    return (
      <span
        style={{
          background: 'rgba(57, 229, 105, 0.15)',
          border: '1px solid #2d6b3c',
          color: '#39e569',
          fontWeight: 700,
          padding: '1px 6px',
          borderRadius: 4,
          fontSize: 10.5,
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
        }}
      >
        {val}
      </span>
    );
  }
  if (['failed', 'dead', 'error', 'crashed'].includes(s)) {
    return (
      <span
        style={{
          background: 'rgba(239, 68, 68, 0.18)',
          border: '1px solid #ef4444',
          color: '#f87171',
          fontWeight: 700,
          padding: '1px 6px',
          borderRadius: 4,
          fontSize: 10.5,
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
        }}
      >
        {val}
      </span>
    );
  }
  if (['exited', 'inactive', 'stopped', 'shut off', 'paused'].includes(s)) {
    return (
      <span
        style={{
          background: 'rgba(255, 255, 255, 0.04)',
          border: '1px solid #1f3324',
          color: '#728c78',
          fontWeight: 600,
          padding: '1px 6px',
          borderRadius: 4,
          fontSize: 10.5,
          textTransform: 'uppercase',
          letterSpacing: '0.04em',
        }}
      >
        {val || '—'}
      </span>
    );
  }
  return (
    <span
      style={{
        background: 'rgba(229, 192, 123, 0.12)',
        border: '1px solid #b48e3a',
        color: '#facc15',
        fontWeight: 600,
        padding: '1px 6px',
        borderRadius: 4,
        fontSize: 10.5,
        textTransform: 'uppercase',
        letterSpacing: '0.04em',
      }}
    >
      {val || '—'}
    </span>
  );
};

function Services({ latest, filter }) {
  const rows = listOf(latest, 'services', 'services');
  const failed = rows.filter((r) => r.active === 'failed').length;
  const active = rows.filter((r) => r.active === 'active').length;

  const cols = [
    {
      key: 'unit',
      label: 'UNIT',
      render: (r) => (
        <span style={{ color: '#e2e8f0', fontWeight: 600, fontFamily: 'JetBrains Mono, monospace' }}>
          {r.unit}
        </span>
      ),
    },
    {
      key: 'active',
      label: 'ACTIVE',
      value: (r) => (r.active === 'failed' ? 0 : r.active === 'active' ? 1 : 2),
      render: (r) => renderStateBadge(r.active),
    },
    {
      key: 'sub',
      label: 'SUBSTATE',
      render: (r) => renderStateBadge(r.sub),
    },
    {
      key: 'load',
      label: 'LOAD',
      render: (r) => <span style={{ color: '#94a3b8', fontSize: 11.5 }}>{r.load}</span>,
    },
    {
      key: 'description',
      label: 'DESCRIPTION',
      render: (r) => <span style={{ color: '#7a9680', fontSize: 11.5 }}>{r.description || '—'}</span>,
    },
  ];

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 10, fontSize: 12 }}>
        <span style={{ background: '#0a160e', border: '1px solid #1a3821', padding: '2px 8px', borderRadius: 5, color: '#a3c4aa', fontWeight: 700 }}>
          {rows.length} Total Units
        </span>
        <span style={{ background: 'rgba(57, 229, 105, 0.12)', border: '1px solid #2d6b3c', padding: '2px 8px', borderRadius: 5, color: '#39e569', fontWeight: 700 }}>
          {active} Active
        </span>
        {failed > 0 ? (
          <span style={{ background: 'rgba(239, 68, 68, 0.15)', border: '1px solid #ef4444', padding: '2px 8px', borderRadius: 5, color: '#f87171', fontWeight: 700 }}>
            {failed} Failed
          </span>
        ) : (
          <span style={{ background: '#0a160e', border: '1px solid #1a3821', padding: '2px 8px', borderRadius: 5, color: '#728c78' }}>
            0 Failed
          </span>
        )}
      </div>
      <DataTable
        columns={cols}
        rows={rows}
        rowKey={(r) => r.unit}
        filter={filter}
        initialSort={{ key: 'active', dir: 'asc' }}
        empty={emptyMsg(latest, 'services', 'systemd services (the collector needs the host D-Bus socket mounted)')}
      />
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
    {
      key: 'name',
      label: 'NAME',
      render: (r) => (
        <span style={{ color: '#e2e8f0', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
          {r.name}
        </span>
      ),
    },
    {
      key: 'runtime',
      label: 'RUNTIME',
      render: (r) => (
        <span style={{ color: '#06b6d4', fontWeight: 600, fontSize: 11 }}>
          {r.runtime}
        </span>
      ),
    },
    {
      key: 'image',
      label: 'IMAGE',
      render: (r) => (
        <span style={{ color: '#94a3b8', fontSize: 11.5 }} title={r.image}>
          {r.image}
        </span>
      ),
    },
    {
      key: 'state',
      label: 'STATE',
      render: (r) => renderStateBadge(r.state || r.status),
    },
    {
      key: 'cpu',
      label: 'CPU %',
      num: true,
      render: (r) => (
        <span style={{ color: '#22d3ee', fontWeight: 700 }}>
          {r.cpu === null ? '—' : `${formatNumber(r.cpu, 1)}%`}
        </span>
      ),
    },
    {
      key: 'mem',
      label: 'MEMORY',
      num: true,
      render: (r) => (
        <span style={{ color: '#06b6d4', fontWeight: 700 }}>
          {r.mem === null ? '—' : formatBytes(r.mem)}
        </span>
      ),
    },
    {
      key: 'status',
      label: 'STATUS',
      render: (r) => <span style={{ color: '#7a9680', fontSize: 11 }}>{r.status || '—'}</span>,
    },
  ];

  return (
    <>
      <SourceBadges sources={containerSources(latest)} />
      <DataTable
        columns={cols}
        rows={rows}
        rowKey={(r, i) => `${r.runtime}-${r.id || r.name}-${i}`}
        filter={filter}
        initialSort={{ key: 'state', dir: 'desc' }}
        empty={emptyMsg(latest, 'containers', 'containers')}
      />
    </>
  );
}

function Vms({ latest, filter }) {
  const rows = listOf(latest, 'vms', 'vms');
  const cols = [
    {
      key: 'name',
      label: 'VM NAME',
      render: (r) => (
        <span style={{ color: '#e2e8f0', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
          {r.name}
        </span>
      ),
    },
    {
      key: 'state',
      label: 'STATE',
      render: (r) => renderStateBadge(r.state || r.status),
    },
    {
      key: 'cpu_count',
      label: 'VCPU',
      num: true,
      render: (r) => <span style={{ color: '#22d3ee', fontWeight: 700 }}>{r.cpu_count ?? '—'}</span>,
    },
    {
      key: 'max_memory',
      label: 'MAX MEMORY',
      render: (r) => <span style={{ color: '#94a3b8' }}>{r.max_memory ? formatBytes(r.max_memory) : '—'}</span>,
    },
    {
      key: 'used_memory',
      label: 'USED MEMORY',
      render: (r) => <span style={{ color: '#06b6d4', fontWeight: 700 }}>{r.used_memory ? formatBytes(r.used_memory) : '—'}</span>,
    },
  ];

  return (
    <>
      <SourceBadges sources={vmSources(latest)} />
      <DataTable
        columns={cols}
        rows={rows}
        rowKey={(r, i) => `${r.name}-${i}`}
        filter={filter}
        empty={emptyMsg(latest, 'vms', 'virtual machines (libvirt / Proxmox not reachable from the collector)')}
      />
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
    {
      key: 'type',
      label: 'PROTO',
      render: (r) => (
        <span style={{ color: '#06b6d4', fontWeight: 700, fontSize: 11 }}>
          {r.type}
        </span>
      ),
    },
    {
      key: 'local',
      label: 'LOCAL ADDRESS',
      render: (r) => (
        <span style={{ color: '#e2e8f0', fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5 }}>
          {r.local}
        </span>
      ),
    },
    {
      key: 'remote',
      label: 'REMOTE ADDRESS',
      render: (r) => (
        <span style={{ color: r.remote === '*' ? '#728c78' : '#94a3b8', fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5 }}>
          {r.remote}
        </span>
      ),
    },
    {
      key: 'state',
      label: 'STATE',
      render: (r) => renderStateBadge(r.state),
    },
    {
      key: 'pid',
      label: 'PID',
      num: true,
      render: (r) => (
        <span style={{ color: '#728c78', fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
          {r.pid ?? '—'}
        </span>
      ),
    },
    {
      key: 'process',
      label: 'PROCESS',
      render: (r) => (
        <span style={{ color: '#39e569', fontWeight: 600 }}>
          {r.process || '—'}
        </span>
      ),
    },
  ];

  const truncated = (latest && listOf(latest, 'connections', 'sockets').length >= 5000);

  return (
    <>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap', marginBottom: 10, fontSize: 12 }}>
        <span style={{ background: '#0a160e', border: '1px solid #1a3821', padding: '2px 8px', borderRadius: 5, color: '#a3c4aa', fontWeight: 700 }}>
          {formatCount(rows.length)} Sockets{truncated ? ' (max 5000)' : ''}
        </span>
        {by.slice(0, 5).map(([k, v]) => (
          <span key={k} style={{ background: 'rgba(255, 255, 255, 0.03)', border: '1px solid #17331e', padding: '2px 8px', borderRadius: 5, color: '#8aa690', fontSize: 11 }}>
            <span style={{ color: '#d8dee9', fontWeight: 700 }}>{k}</span>: {v}
          </span>
        ))}
      </div>
      <DataTable
        columns={cols}
        rows={rows}
        rowKey={(r, i) => `${r.pid}-${r.local}-${r.remote}-${i}`}
        filter={filter}
        initialSort={{ key: 'state', dir: 'asc' }}
        empty={emptyMsg(latest, 'connections', 'sockets')}
      />
    </>
  );
}

function Storage({ latest, filter }) {
  const st = useMemo(() => storageSummary(latest), [latest]);

  const fsCols = [
    {
      key: 'mount',
      label: 'MOUNT POINT',
      render: (r) => (
        <span style={{ color: '#39e569', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
          {r.mount}
        </span>
      ),
    },
    {
      key: 'device',
      label: 'DEVICE',
      render: (r) => <span style={{ color: '#94a3b8', fontSize: 11 }}>{r.device}</span>,
    },
    {
      key: 'fs',
      label: 'FILESYSTEM',
      render: (r) => <span style={{ color: '#728c78', fontSize: 11 }}>{r.fs}</span>,
    },
    {
      key: 'total',
      label: 'TOTAL',
      num: true,
      render: (r) => <span style={{ color: '#cbd5e1' }}>{formatBytes(r.total)}</span>,
    },
    {
      key: 'used',
      label: 'USED',
      num: true,
      render: (r) => <span style={{ color: '#06b6d4', fontWeight: 700 }}>{formatBytes(r.used)}</span>,
    },
    {
      key: 'free',
      label: 'FREE',
      num: true,
      render: (r) => <span style={{ color: '#39e569' }}>{formatBytes(r.free)}</span>,
    },
    {
      key: 'pct',
      label: 'UTILIZATION',
      num: true,
      render: (r) => (r.pct === null ? <span className="tone-dim">{r.status}</span> : (
        <span className="row" style={{ gap: 8, justifyContent: 'flex-end' }}>
          <span style={{ width: 90, display: 'inline-flex' }}>
            <Meter pct={r.pct} />
          </span>
          <span style={{ color: r.pct >= 90 ? '#f87171' : r.pct >= 75 ? '#facc15' : '#39e569', fontWeight: 700, minWidth: '3em' }}>
            {formatPercent(r.pct, 0)}
          </span>
        </span>
      )),
    },
  ];

  const ioCols = [
    {
      key: 'device',
      label: 'DEVICE',
      render: (r) => (
        <span style={{ color: '#e2e8f0', fontWeight: 700, fontFamily: 'JetBrains Mono, monospace' }}>
          {r.device}
        </span>
      ),
    },
    {
      key: 'read_bytes',
      label: 'READ BYTES',
      num: true,
      render: (r) => <span style={{ color: '#22d3ee', fontWeight: 700 }}>{formatBytes(r.read_bytes)}</span>,
    },
    {
      key: 'write_bytes',
      label: 'WRITTEN BYTES',
      num: true,
      render: (r) => <span style={{ color: '#fbbf24', fontWeight: 700 }}>{formatBytes(r.write_bytes)}</span>,
    },
    {
      key: 'read_count',
      label: 'TOTAL READS',
      num: true,
      render: (r) => <span style={{ color: '#cbd5e1' }}>{formatCount(r.read_count)}</span>,
    },
    {
      key: 'write_count',
      label: 'TOTAL WRITES',
      num: true,
      render: (r) => <span style={{ color: '#cbd5e1' }}>{formatCount(r.write_count)}</span>,
    },
  ];

  if (!st.available) return <Empty>{emptyMsg(latest, 'storage', 'storage data')}</Empty>;

  return (
    <>
      <div style={{ marginBottom: 6, fontSize: 12, fontWeight: 700, color: '#a3c4aa', letterSpacing: '0.04em' }}>
        MOUNTED FILESYSTEMS
      </div>
      <DataTable columns={fsCols} rows={st.filesystems} rowKey={(r) => r.mount + r.device} filter={filter} />

      <div style={{ margin: '18px 0 6px', fontSize: 12, fontWeight: 700, color: '#a3c4aa', letterSpacing: '0.04em' }}>
        DISK I/O TELEMETRY (CUMULATIVE SINCE BOOT)
      </div>
      <DataTable columns={ioCols} rows={st.diskIo} rowKey={(r) => r.device} filter={filter} initialSort={{ key: 'device', dir: 'asc' }} empty="no disk counters" />

      {st.raid && (
        <div style={{ marginTop: 16 }}>
          <div style={{ marginBottom: 6, fontSize: 12, fontWeight: 700, color: '#a3c4aa' }}>
            SOFTWARE RAID: {st.raid.detected ? `${(st.raid.arrays || []).length} array(s) detected` : 'none detected'}
          </div>
          {st.raid.detected && <pre className="pre">{st.raid.mdstat_raw}</pre>}
        </div>
      )}
    </>
  );
}

function Capabilities({ caps }) {
  const entries = Object.entries(caps || {});
  if (entries.length === 0) {
    return <Empty>No collector capabilities stored for this node yet.</Empty>;
  }

  return (
    <div>
      <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: '#a3c4aa', letterSpacing: '0.04em' }}>
          HOST COLLECTOR CAPABILITY MATRIX
        </span>
        <span style={{ fontSize: 11, color: '#728c78', fontFamily: 'JetBrains Mono, monospace' }}>
          {entries.length} features probed
        </span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: 12 }}>
        {entries.map(([name, item]) => {
          const status = (item && item.status) || 'unknown';
          const isAvail = status === 'available';
          const isNotConfig = status === 'not_configured';
          const isDenied = status === 'permission_denied';

          const cardBg = isAvail
            ? 'rgba(12, 28, 16, 0.7)'
            : isNotConfig
            ? 'rgba(255, 255, 255, 0.02)'
            : isDenied
            ? 'rgba(239, 68, 68, 0.08)'
            : 'rgba(245, 158, 11, 0.08)';

          const borderColor = isAvail
            ? '#23522f'
            : isNotConfig
            ? '#162c1d'
            : isDenied
            ? '#ef444455'
            : '#e5c07b44';

          return (
            <div
              key={name}
              style={{
                background: cardBg,
                border: `1px solid ${borderColor}`,
                borderRadius: 10,
                padding: '12px 14px',
                display: 'flex',
                flexDirection: 'column',
                gap: 6,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 13, fontWeight: 800, color: '#fff', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                  {name}
                </span>
                {renderStateBadge(status)}
              </div>

              {item?.source && (
                <div style={{ fontSize: 11.5, color: '#8da693' }}>
                  source: <span style={{ color: '#22d3ee', fontFamily: 'JetBrains Mono, monospace' }}>{item.source}</span>
                </div>
              )}

              {item?.sources && (
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', marginTop: 2 }}>
                  {Array.isArray(item.sources)
                    ? item.sources.map((s) => (
                        <span key={s} style={{ fontSize: 10.5, background: 'rgba(255,255,255,0.04)', border: '1px solid #1a3821', padding: '1px 6px', borderRadius: 4, color: '#a3c4aa' }}>
                          {s}
                        </span>
                      ))
                    : Object.entries(item.sources).map(([k, active]) => (
                        <span
                          key={k}
                          style={{
                            fontSize: 10.5,
                            background: active ? 'rgba(57,229,105,0.1)' : 'rgba(255,255,255,0.03)',
                            border: `1px solid ${active ? '#2d6b3c' : '#1a3821'}`,
                            padding: '1px 6px',
                            borderRadius: 4,
                            color: active ? '#39e569' : '#6b7a6f',
                            fontWeight: active ? 700 : 500,
                          }}
                        >
                          {k}: {active ? 'active' : 'inactive'}
                        </span>
                      ))}
                </div>
              )}

              {item?.reason && (
                <div style={{ fontSize: 11, color: isDenied ? '#fca5a5' : '#8da693', fontStyle: 'italic', marginTop: 2 }}>
                  {item.reason}
                </div>
              )}

              {item?.buffer_seconds && (
                <div style={{ fontSize: 11, color: '#728c78', fontFamily: 'JetBrains Mono, monospace', marginTop: 2 }}>
                  buffer: {item.buffer_seconds}s • interval: {item.interval_seconds}s
                </div>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}

function emptyMsg(latest, cat, what) {
  const status = agentStatus(latest, cat);
  if (status === null) return `No ${what} yet. The host collector has not reported this category.`;
  if (status === 'unavailable' || status === 'permission_denied') return `The collector reports ${what} as ${status.replace('_', ' ')} on this host.`;
  return `No ${what} reported.`;
}

export default function InventoryTab({ node, state, section, setSection, onBack, onChangeView }) {
  const [filter, setFilter] = useState('');
  const latest = state.data && state.data.latest;

  if (state.loading && !state.data) return <Empty><span className="spinner" /> loading telemetry…</Empty>;
  if (!state.data) return <ErrorLine>{state.error || 'No data'}</ErrorLine>;
  if (!latest) return <ErrorLine>{(state.data.errors && state.data.errors.latest) || 'No telemetry returned'}</ErrorLine>;
  const rawCaps = (node && node.capabilities) || {};
  const caps = (rawCaps && typeof rawCaps === 'object' && rawCaps.capabilities) ? rawCaps.capabilities : rawCaps;

  return (
    <>
      <NodeHeaderNav
        node={node}
        currentView="inventory"
        onViewChange={onChangeView}
        onBack={onBack}
      />

      {/* Main Panel Box */}
      <Box
        n={3}
        title="SYSTEM INVENTORY"
        hot
        controls={
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <Chips value={section} onChange={setSection} options={SECTIONS} />
            {section !== 'caps' && (
              <input
                className="in"
                style={{
                  width: 160,
                  background: '#040805',
                  border: '1px solid #1a3821',
                  borderRadius: 6,
                  padding: '2px 8px',
                  fontSize: 11.5,
                  color: '#d8dee9',
                  outline: 'none',
                  fontFamily: 'JetBrains Mono, monospace',
                }}
                placeholder="filter records..."
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
              />
            )}
          </div>
        }
      >
        <div
          className="box-scroll"
          style={{
            maxHeight: 'calc(100vh - 210px)',
            border: '1px solid #142e1a',
            borderRadius: 8,
            background: 'rgba(6, 12, 8, 0.6)',
            padding: '12px 14px',
            overflowY: 'auto',
            marginTop: 4,
          }}
        >
          {section === 'services' && <Services latest={latest} filter={filter} />}
          {section === 'containers' && <Containers latest={latest} filter={filter} />}
          {section === 'vms' && <Vms latest={latest} filter={filter} />}
          {section === 'sockets' && <Sockets latest={latest} filter={filter} />}
          {section === 'storage' && <Storage latest={latest} filter={filter} />}
          {section === 'caps' && <Capabilities caps={caps} />}
        </div>
      </Box>
    </>
  );
}

export { SECTIONS as INVENTORY_SECTIONS };
