import { useEffect, useMemo, useRef, useState } from 'react';
import { Badge, Box, Chips, DataTable, Empty, ErrorLine, Meter } from './ui';
import NodeHeaderNav from './NodeHeaderNav';
import { agentStatus, containerSources, listOf, storageSummary, vmSources } from '../lib/metrics';
import { formatBytes, formatNumber, formatPercent, formatCount } from '../lib/format';
import { api } from '../api';


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

function Containers({ latest, filter, containerOverrides = {}, onActionContainer, onViewLogs }) {
  const rows = listOf(latest, 'containers', 'containers').map((c) => {
    const id = c.id || c.name;
    const name = c.name || id;
    let state = c.state;
    let status = c.status;
    if (containerOverrides[id]) {
      state = containerOverrides[id].state;
      status = containerOverrides[id].status;
    } else if (containerOverrides[name]) {
      state = containerOverrides[name].state;
      status = containerOverrides[name].status;
    }
    return {
      ...c,
      state,
      status,
      cpu: c.metrics && typeof c.metrics.cpu_percent === 'number' ? c.metrics.cpu_percent : null,
      mem: c.metrics && typeof c.metrics.memory_usage_bytes === 'number' ? c.metrics.memory_usage_bytes : null,
      memLimit: c.metrics && typeof c.metrics.memory_limit_bytes === 'number' ? c.metrics.memory_limit_bytes : null,
    };
  });

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
    {
      key: 'actions',
      label: 'ACTIONS',
      render: (r) => {
        const stateStr = String(r.state || r.status || '').toLowerCase();
        const isRunning = stateStr.includes('running') || stateStr === 'active' || stateStr === 'up';
        return (
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            {isRunning ? (
              <>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={(e) => {
                    e.stopPropagation();
                    onActionContainer && onActionContainer({ action: 'stop', container: r });
                  }}
                  style={{
                    background: 'rgba(239, 68, 68, 0.12)',
                    border: '1px solid #7f1d1d',
                    color: '#f87171',
                    padding: '2px 7px',
                    fontSize: 10.5,
                    fontWeight: 700,
                    letterSpacing: '0.04em',
                    borderRadius: 4,
                  }}
                  title="Stop this running container"
                >
                  STOP
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={(e) => {
                    e.stopPropagation();
                    onActionContainer && onActionContainer({ action: 'restart', container: r });
                  }}
                  style={{
                    background: 'rgba(245, 158, 11, 0.12)',
                    border: '1px solid #78350f',
                    color: '#fbbf24',
                    padding: '2px 7px',
                    fontSize: 10.5,
                    fontWeight: 700,
                    letterSpacing: '0.04em',
                    borderRadius: 4,
                  }}
                  title="Restart container"
                >
                  RESTART
                </button>
              </>
            ) : (
              <button
                type="button"
                className="btn btn-sm"
                onClick={(e) => {
                  e.stopPropagation();
                  onActionContainer && onActionContainer({ action: 'start', container: r });
                }}
                style={{
                  background: 'rgba(34, 197, 94, 0.12)',
                  border: '1px solid #14532d',
                  color: '#4ade80',
                  padding: '2px 7px',
                  fontSize: 10.5,
                  fontWeight: 700,
                  letterSpacing: '0.04em',
                  borderRadius: 4,
                }}
                title="Start container"
              >
                START
              </button>
            )}
            <button
              type="button"
              className="btn btn-sm"
              onClick={(e) => {
                e.stopPropagation();
                onViewLogs && onViewLogs(r);
              }}
              style={{
                background: 'rgba(6, 182, 212, 0.12)',
                border: '1px solid #164e63',
                color: '#22d3ee',
                padding: '2px 7px',
                fontSize: 10.5,
                fontWeight: 700,
                letterSpacing: '0.04em',
                borderRadius: 4,
              }}
              title="View container logs"
            >
              LOGS
            </button>
          </div>
        );
      },
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

function Vms({ latest, filter, vmOverrides = {}, onActionVm }) {
  const rows = listOf(latest, 'vms', 'vms').map((v) => {
    const targetId = v.name || (v.vmid ? String(v.vmid) : '');
    let state = v.state;
    let status = v.status;
    if (vmOverrides[targetId]) {
      state = vmOverrides[targetId].state;
      status = vmOverrides[targetId].status;
    } else if (v.name && vmOverrides[v.name]) {
      state = vmOverrides[v.name].state;
      status = vmOverrides[v.name].status;
    }
    return {
      ...v,
      state,
      status,
    };
  });
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
    {
      key: 'actions',
      label: 'ACTIONS',
      render: (r) => {
        const stateStr = String(r.state || r.status || '').toLowerCase();
        const isRunning = stateStr.includes('running') || stateStr === 'active' || stateStr === 'up';
        return (
          <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
            {isRunning ? (
              <>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={(e) => {
                    e.stopPropagation();
                    onActionVm && onActionVm({ action: 'stop', vm: r });
                  }}
                  style={{
                    background: 'rgba(239, 68, 68, 0.12)',
                    border: '1px solid #7f1d1d',
                    color: '#f87171',
                    padding: '2px 7px',
                    fontSize: 10.5,
                    fontWeight: 700,
                    letterSpacing: '0.04em',
                    borderRadius: 4,
                  }}
                  title="Stop virtual machine"
                >
                  STOP
                </button>
                <button
                  type="button"
                  className="btn btn-sm"
                  onClick={(e) => {
                    e.stopPropagation();
                    onActionVm && onActionVm({ action: 'restart', vm: r });
                  }}
                  style={{
                    background: 'rgba(245, 158, 11, 0.12)',
                    border: '1px solid #78350f',
                    color: '#fbbf24',
                    padding: '2px 7px',
                    fontSize: 10.5,
                    fontWeight: 700,
                    letterSpacing: '0.04em',
                    borderRadius: 4,
                  }}
                  title="Restart virtual machine"
                >
                  RESTART
                </button>
              </>
            ) : (
              <button
                type="button"
                className="btn btn-sm"
                onClick={(e) => {
                  e.stopPropagation();
                  onActionVm && onActionVm({ action: 'start', vm: r });
                }}
                style={{
                  background: 'rgba(34, 197, 94, 0.12)',
                  border: '1px solid #14532d',
                  color: '#4ade80',
                  padding: '2px 7px',
                  fontSize: 10.5,
                  fontWeight: 700,
                  letterSpacing: '0.04em',
                  borderRadius: 4,
                }}
                title="Start virtual machine"
              >
                START
              </button>
            )}
          </div>
        );
      },
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
  if (status === 'not_configured') return `No ${what} configured or detected on this host.`;
  if (status === 'unavailable' || status === 'permission_denied') return `The collector reports ${what} as ${status.replace('_', ' ')} on this host.`;
  if (status === 'available') return `No active ${what} found on this host.`;
  if (status === null) return `No ${what} detected on this host.`;
  return `No ${what} reported.`;
}

export default function InventoryTab({ node, state, section, setSection, onBack, onChangeView, onToast, onRefresh, onKilledPids }) {
  const [filter, setFilter] = useState('');
  const [containerOverrides, setContainerOverrides] = useState(() => ({}));
  const [vmOverrides, setVmOverrides] = useState(() => ({}));

  // Workload Lifecycle Action Modals
  const [pendingContainerAction, setPendingContainerAction] = useState(null);
  const [executingContainerAction, setExecutingContainerAction] = useState(false);

  const [pendingVmAction, setPendingVmAction] = useState(null);
  const [executingVmAction, setExecutingVmAction] = useState(false);
  const [forceVm, setForceVm] = useState(false);

  // Instant Container Log Stream Modal
  const [logContainer, setLogContainer] = useState(null);
  const [logData, setLogData] = useState('');
  const [logLoading, setLogLoading] = useState(false);
  const [logError, setLogError] = useState(null);
  const [logTail, setLogTail] = useState(200);
  const [logWrap, setLogWrap] = useState(true);
  const [copied, setCopied] = useState(false);
  const logsContainerRef = useRef(null);

  const latest = state.data && state.data.latest;

  useEffect(() => {
    if (logsContainerRef.current) {
      logsContainerRef.current.scrollTop = logsContainerRef.current.scrollHeight;
    }
  }, [logData]);

  async function handleConfirmContainerAction() {
    if (!pendingContainerAction || !node) return;
    setExecutingContainerAction(true);
    const { action, container } = pendingContainerAction;
    const targetId = container.id || container.name;
    const targetName = container.name || targetId;

    try {
      if (action === 'stop') {
        const res = await api.stopContainer(node.id, targetId, 10);
        setContainerOverrides((prev) => ({
          ...prev,
          [targetId]: { state: 'exited', status: 'Exited (manual stop)' },
          [targetName]: { state: 'exited', status: 'Exited (manual stop)' },
        }));
        if (res && Array.isArray(res.stopped_pids) && res.stopped_pids.length > 0 && onKilledPids) {
          onKilledPids(res.stopped_pids);
        }
        onToast && onToast(`Container ${targetName} stopped`);
      } else if (action === 'start') {
        await api.startContainer(node.id, targetId);
        setContainerOverrides((prev) => ({
          ...prev,
          [targetId]: { state: 'running', status: 'Up (just started)' },
          [targetName]: { state: 'running', status: 'Up (just started)' },
        }));
        onToast && onToast(`Container ${targetName} started`);
      } else if (action === 'restart') {
        await api.restartContainer(node.id, targetId, 10);
        setContainerOverrides((prev) => ({
          ...prev,
          [targetId]: { state: 'running', status: 'Up (just restarted)' },
          [targetName]: { state: 'running', status: 'Up (just restarted)' },
        }));
        onToast && onToast(`Container ${targetName} restarted`);
      }
      setPendingContainerAction(null);
      if (onRefresh) onRefresh();
    } catch (err) {
      onToast && onToast(`Failed to ${action} container: ${err.message}`, true);
    } finally {
      setExecutingContainerAction(false);
    }
  }

  async function handleConfirmVmAction() {
    if (!pendingVmAction || !node) return;
    setExecutingVmAction(true);
    const { action, vm } = pendingVmAction;
    const targetId = vm.name || (vm.vmid ? String(vm.vmid) : '');
    const targetName = vm.name || targetId;

    try {
      if (action === 'stop') {
        await api.stopVm(node.id, targetId, forceVm);
        setVmOverrides((prev) => ({
          ...prev,
          [targetId]: { state: 'shut off', status: 'shut off' },
          [targetName]: { state: 'shut off', status: 'shut off' },
        }));
        onToast && onToast(`Virtual machine ${targetName} stopped`);
      } else if (action === 'start') {
        await api.startVm(node.id, targetId);
        setVmOverrides((prev) => ({
          ...prev,
          [targetId]: { state: 'running', status: 'running' },
          [targetName]: { state: 'running', status: 'running' },
        }));
        onToast && onToast(`Virtual machine ${targetName} started`);
      } else if (action === 'restart') {
        await api.restartVm(node.id, targetId, forceVm);
        setVmOverrides((prev) => ({
          ...prev,
          [targetId]: { state: 'running', status: 'running' },
          [targetName]: { state: 'running', status: 'running' },
        }));
        onToast && onToast(`Virtual machine ${targetName} restarted`);
      }
      setPendingVmAction(null);
      if (onRefresh) onRefresh();
    } catch (err) {
      onToast && onToast(`Failed to ${action} VM: ${err.message}`, true);
    } finally {
      setExecutingVmAction(false);
    }
  }

  async function fetchContainerLogs(c, tail = logTail) {
    if (!c || !node) return;
    setLogLoading(true);
    setLogError(null);
    const targetId = c.id || c.name;
    try {
      const res = await api.getContainerLogs(node.id, targetId, tail);
      setLogData(res.logs || '(no logs produced by container)');
    } catch (err) {
      setLogError(err.message || 'Failed to fetch logs');
    } finally {
      setLogLoading(false);
    }
  }

  function handleOpenLogs(c) {
    setLogContainer(c);
    setLogData('');
    setLogError(null);
    fetchContainerLogs(c, logTail);
  }

  function handleCopyLogs() {
    if (!logData) return;
    navigator.clipboard.writeText(logData).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }

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
          {section === 'containers' && (
            <Containers
              latest={latest}
              filter={filter}
              containerOverrides={containerOverrides}
              onActionContainer={(act) => setPendingContainerAction(act)}
              onViewLogs={handleOpenLogs}
            />
          )}
          {section === 'vms' && (
            <Vms
              latest={latest}
              filter={filter}
              vmOverrides={vmOverrides}
              onActionVm={(act) => {
                setPendingVmAction(act);
                setForceVm(false);
              }}
            />
          )}
          {section === 'sockets' && <Sockets latest={latest} filter={filter} />}
          {section === 'storage' && <Storage latest={latest} filter={filter} />}
          {section === 'caps' && <Capabilities caps={caps} />}
        </div>
      </Box>

      {/* Container Action Confirmation Modal */}
      {pendingContainerAction && (
        <div
          className="modal-back"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget && !executingContainerAction) setPendingContainerAction(null);
          }}
        >
          <div
            className="box modal hot"
            role="dialog"
            aria-modal="true"
            style={{
              maxWidth: 480,
              width: '90%',
              padding: '22px 20px',
              background: '#070c08',
              border: `1px solid ${
                pendingContainerAction.action === 'stop'
                  ? '#7f1d1d'
                  : pendingContainerAction.action === 'restart'
                  ? '#78350f'
                  : '#14532d'
              }`,
              borderRadius: 8,
              boxShadow: '0 10px 25px rgba(0,0,0,0.8)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              {pendingContainerAction.action === 'stop' && (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
                  <line x1="9" y1="9" x2="15" y2="15" />
                  <line x1="15" y1="9" x2="9" y2="15" />
                </svg>
              )}
              {pendingContainerAction.action === 'restart' && (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="23 4 23 10 17 10" />
                  <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
                </svg>
              )}
              {pendingContainerAction.action === 'start' && (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4ade80" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polygon points="5 3 19 12 5 21 5 3" />
                </svg>
              )}
              <h3
                style={{
                  margin: 0,
                  fontSize: 16,
                  fontWeight: 800,
                  color:
                    pendingContainerAction.action === 'stop'
                      ? '#f87171'
                      : pendingContainerAction.action === 'restart'
                      ? '#fbbf24'
                      : '#4ade80',
                  letterSpacing: '0.04em',
                }}
              >
                {pendingContainerAction.action.toUpperCase()} CONTAINER
              </h3>
            </div>

            <p style={{ margin: '0 0 16px', fontSize: 13, color: '#d8dee9', lineHeight: 1.5 }}>
              Are you sure you want to {pendingContainerAction.action} container{' '}
              <b>{pendingContainerAction.container.name || pendingContainerAction.container.id}</b>
              {pendingContainerAction.container.image ? ` (${pendingContainerAction.container.image})` : ''}?
            </p>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                type="button"
                className="btn"
                onClick={() => setPendingContainerAction(null)}
                disabled={executingContainerAction}
                style={{ background: '#122416', border: '1px solid #244b2c', color: '#a3c4aa' }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-hot"
                onClick={handleConfirmContainerAction}
                disabled={executingContainerAction}
                style={{
                  background:
                    pendingContainerAction.action === 'stop'
                      ? '#7f1d1d'
                      : pendingContainerAction.action === 'restart'
                      ? '#78350f'
                      : '#14532d',
                  border: `1px solid ${
                    pendingContainerAction.action === 'stop'
                      ? '#dc2626'
                      : pendingContainerAction.action === 'restart'
                      ? '#d97706'
                      : '#16a34a'
                  }`,
                  color: '#fff',
                  fontWeight: 800,
                  minWidth: 120,
                }}
              >
                {executingContainerAction
                  ? `${pendingContainerAction.action === 'stop' ? 'Stopping' : pendingContainerAction.action === 'restart' ? 'Restarting' : 'Starting'}…`
                  : `${pendingContainerAction.action === 'stop' ? 'Stop Container' : pendingContainerAction.action === 'restart' ? 'Restart Container' : 'Start Container'}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* VM Action Confirmation Modal */}
      {pendingVmAction && (
        <div
          className="modal-back"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.75)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget && !executingVmAction) setPendingVmAction(null);
          }}
        >
          <div
            className="box modal hot"
            role="dialog"
            aria-modal="true"
            style={{
              maxWidth: 480,
              width: '90%',
              padding: '22px 20px',
              background: '#070c08',
              border: `1px solid ${
                pendingVmAction.action === 'stop'
                  ? '#7f1d1d'
                  : pendingVmAction.action === 'restart'
                  ? '#78350f'
                  : '#14532d'
              }`,
              borderRadius: 8,
              boxShadow: '0 10px 25px rgba(0,0,0,0.8)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              {pendingVmAction.action === 'stop' && (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#ef4444" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
                  <line x1="8" y1="21" x2="16" y2="21"/>
                  <line x1="12" y1="17" x2="12" y2="21"/>
                </svg>
              )}
              {pendingVmAction.action === 'restart' && (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#fbbf24" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="23 4 23 10 17 10" />
                  <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
                </svg>
              )}
              {pendingVmAction.action === 'start' && (
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#4ade80" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polygon points="5 3 19 12 5 21 5 3" />
                </svg>
              )}
              <h3
                style={{
                  margin: 0,
                  fontSize: 16,
                  fontWeight: 800,
                  color:
                    pendingVmAction.action === 'stop'
                      ? '#f87171'
                      : pendingVmAction.action === 'restart'
                      ? '#fbbf24'
                      : '#4ade80',
                  letterSpacing: '0.04em',
                }}
              >
                {pendingVmAction.action.toUpperCase()} VIRTUAL MACHINE
              </h3>
            </div>

            <p style={{ margin: '0 0 16px', fontSize: 13, color: '#d8dee9', lineHeight: 1.5 }}>
              Are you sure you want to {pendingVmAction.action} virtual machine <b>{pendingVmAction.vm.name}</b>
              {pendingVmAction.vm.runtime ? ` (${pendingVmAction.vm.runtime})` : ''}?
            </p>

            {pendingVmAction.action === 'stop' && (
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: '#cbd5e1', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={forceVm}
                    onChange={(e) => setForceVm(e.target.checked)}
                    style={{ accentColor: '#ef4444' }}
                  />
                  Force immediate power off (destroy / hard stop)
                </label>
              </div>
            )}

            {pendingVmAction.action === 'restart' && (
              <div style={{ marginBottom: 16 }}>
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 12, color: '#cbd5e1', cursor: 'pointer' }}>
                  <input
                    type="checkbox"
                    checked={forceVm}
                    onChange={(e) => setForceVm(e.target.checked)}
                    style={{ accentColor: '#fbbf24' }}
                  />
                  Hard reset instead of graceful reboot
                </label>
              </div>
            )}

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                type="button"
                className="btn"
                onClick={() => setPendingVmAction(null)}
                disabled={executingVmAction}
                style={{ background: '#122416', border: '1px solid #244b2c', color: '#a3c4aa' }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn btn-hot"
                onClick={handleConfirmVmAction}
                disabled={executingVmAction}
                style={{
                  background:
                    pendingVmAction.action === 'stop'
                      ? '#7f1d1d'
                      : pendingVmAction.action === 'restart'
                      ? '#78350f'
                      : '#14532d',
                  border: `1px solid ${
                    pendingVmAction.action === 'stop'
                      ? '#dc2626'
                      : pendingVmAction.action === 'restart'
                      ? '#d97706'
                      : '#16a34a'
                  }`,
                  color: '#fff',
                  fontWeight: 800,
                  minWidth: 120,
                }}
              >
                {executingVmAction
                  ? `${pendingVmAction.action === 'stop' ? 'Stopping' : pendingVmAction.action === 'restart' ? 'Restarting' : 'Starting'}…`
                  : `${pendingVmAction.action === 'stop' ? (forceVm ? 'Force Stop' : 'Graceful Stop') : pendingVmAction.action === 'restart' ? (forceVm ? 'Hard Reset' : 'Reboot VM') : 'Start VM'}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Instant Container Log Stream Modal */}
      {logContainer && (
        <div
          className="modal-back"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0, 0, 0, 0.8)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setLogContainer(null);
          }}
        >
          <div
            className="box modal hot"
            role="dialog"
            aria-modal="true"
            style={{
              maxWidth: 820,
              width: '94%',
              maxHeight: '90vh',
              display: 'flex',
              flexDirection: 'column',
              padding: '18px 20px',
              background: '#040805',
              border: '1px solid #1a3d24',
              borderRadius: 8,
              boxShadow: '0 12px 30px rgba(0,0,0,0.9)',
            }}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#22d3ee" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <polyline points="4 17 10 11 4 5" />
                  <line x1="12" y1="19" x2="20" y2="19" />
                </svg>
                <div>
                  <h3 style={{ margin: 0, fontSize: 15, fontWeight: 800, color: '#fff', letterSpacing: '0.03em', fontFamily: 'JetBrains Mono, monospace' }}>
                    CONTAINER LOGS: {logContainer.name || logContainer.id}
                  </h3>
                  <div style={{ fontSize: 11, color: '#7a9680', marginTop: 2 }}>
                    Image: <span style={{ color: '#a3c4aa' }}>{logContainer.image || '—'}</span> &bull; Runtime: <span style={{ color: '#06b6d4' }}>{logContainer.runtime || 'docker'}</span>
                  </div>
                </div>
              </div>

              {/* Close Button */}
              <button
                type="button"
                className="btn btn-sm"
                onClick={() => setLogContainer(null)}
                style={{
                  background: 'transparent',
                  border: '1px solid #244b2c',
                  color: '#94a3b8',
                  padding: '4px 8px',
                  borderRadius: 4,
                  cursor: 'pointer',
                }}
                title="Close logs"
              >
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="18" y1="6" x2="6" y2="18" />
                  <line x1="6" y1="6" x2="18" y2="18" />
                </svg>
              </button>
            </div>

            {/* Modal Control Toolbar */}
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'space-between',
                flexWrap: 'wrap',
                gap: 8,
                padding: '8px 10px',
                background: '#071009',
                border: '1px solid #142e1a',
                borderRadius: 6,
                marginBottom: 10,
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <span style={{ fontSize: 11, color: '#728c78', fontWeight: 600 }}>TAIL:</span>
                {[50, 100, 200, 500].map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => {
                      setLogTail(t);
                      fetchContainerLogs(logContainer, t);
                    }}
                    style={{
                      background: logTail === t ? 'rgba(6, 182, 212, 0.2)' : 'transparent',
                      border: `1px solid ${logTail === t ? '#06b6d4' : '#1a3821'}`,
                      color: logTail === t ? '#22d3ee' : '#728c78',
                      fontSize: 10.5,
                      fontWeight: 700,
                      padding: '2px 7px',
                      borderRadius: 4,
                      cursor: 'pointer',
                    }}
                  >
                    {t}
                  </button>
                ))}
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <button
                  type="button"
                  onClick={() => setLogWrap(!logWrap)}
                  style={{
                    background: logWrap ? 'rgba(57, 229, 105, 0.12)' : 'transparent',
                    border: `1px solid ${logWrap ? '#2d6b3c' : '#1a3821'}`,
                    color: logWrap ? '#39e569' : '#728c78',
                    fontSize: 11,
                    fontWeight: 600,
                    padding: '3px 8px',
                    borderRadius: 4,
                    cursor: 'pointer',
                  }}
                  title="Toggle text wrapping"
                >
                  {logWrap ? 'Wrap: On' : 'Wrap: Off'}
                </button>

                <button
                  type="button"
                  onClick={handleCopyLogs}
                  disabled={!logData || logLoading}
                  style={{
                    background: copied ? 'rgba(57, 229, 105, 0.15)' : 'transparent',
                    border: `1px solid ${copied ? '#39e569' : '#1a3821'}`,
                    color: copied ? '#39e569' : '#a3c4aa',
                    fontSize: 11,
                    fontWeight: 600,
                    padding: '3px 8px',
                    borderRadius: 4,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 5,
                  }}
                  title="Copy log text"
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <rect x="9" y="9" width="13" height="13" rx="2" ry="2" />
                    <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1" />
                  </svg>
                  {copied ? 'Copied' : 'Copy'}
                </button>

                <button
                  type="button"
                  onClick={() => fetchContainerLogs(logContainer, logTail)}
                  disabled={logLoading}
                  style={{
                    background: 'rgba(6, 182, 212, 0.12)',
                    border: '1px solid #164e63',
                    color: '#22d3ee',
                    fontSize: 11,
                    fontWeight: 700,
                    padding: '3px 9px',
                    borderRadius: 4,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 5,
                  }}
                  title="Refresh logs"
                >
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <polyline points="23 4 23 10 17 10" />
                    <path d="M20.49 15a9 9 0 1 1-2.12-9.36L23 10" />
                  </svg>
                  {logLoading ? 'Refreshing…' : 'Refresh'}
                </button>
              </div>
            </div>

            {/* Log Terminal Window */}
            <div
              ref={logsContainerRef}
              style={{
                flex: 1,
                minHeight: 280,
                maxHeight: 520,
                background: '#020503',
                border: '1px solid #142e1a',
                borderRadius: 6,
                padding: '12px 14px',
                overflowY: 'auto',
                overflowX: logWrap ? 'hidden' : 'auto',
                fontFamily: 'JetBrains Mono, monospace',
                fontSize: 11.5,
                lineHeight: 1.5,
                color: '#d8dee9',
              }}
            >
              {logLoading && !logData && (
                <div style={{ color: '#728c78', padding: '16px 0', display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span className="spinner" /> Streaming container logs…
                </div>
              )}
              {logError && (
                <div style={{ color: '#f87171', background: 'rgba(239,68,68,0.1)', padding: '8px 12px', borderRadius: 4, border: '1px solid #7f1d1d' }}>
                  Failed to fetch logs: {logError}
                </div>
              )}
              {!logLoading && !logError && !logData && (
                <div style={{ color: '#566e5d' }}>(no output produced by container)</div>
              )}
              {logData && (
                <pre
                  style={{
                    margin: 0,
                    fontFamily: 'inherit',
                    fontSize: 'inherit',
                    whiteSpace: logWrap ? 'pre-wrap' : 'pre',
                    wordBreak: logWrap ? 'break-word' : 'normal',
                    color: '#c0caf5',
                  }}
                >
                  {logData}
                </pre>
              )}
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export { SECTIONS as INVENTORY_SECTIONS };
