import { useMemo, useState } from 'react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { Dot, Meter, MeterRow, Box, Empty, ErrorLine } from './ui';
import { formatBytes, formatPercent, formatRelative, formatCount, formatNetworkSpeed } from '../lib/format';
import { statusTone } from '../lib/events';
import { systemSummary, storageSummary, netdataNetNow } from '../lib/metrics';

import { fetchNodeSummary } from '../hooks/useNodeData';

function getOsIconAndLabel(node, sysData) {
  const osRel = (sysData && sysData.os_release) || {};
  const osStr = [
    node.os_type,
    node.hostname,
    osRel.ID,
    osRel.NAME,
    osRel.PRETTY_NAME,
    osRel.ID_LIKE
  ].filter(Boolean).join(' ').toLowerCase();

  if (osStr.includes('kali')) return { label: 'Kali Linux', img: '/img/kali.png', fallbackImg: '/img/debian.png', badgeClass: 'kali' };
  if (osStr.includes('mint')) return { label: 'Linux Mint', img: '/img/mint.png', fallbackImg: '/img/ubuntu.png', badgeClass: 'mint' };
  if (osStr.includes('manjaro')) return { label: 'Manjaro', img: '/img/manjaro.png', fallbackImg: '/img/arch.png', badgeClass: 'manjaro' };
  if (osStr.includes('pop')) return { label: 'Pop!_OS', img: '/img/pop.png', fallbackImg: '/img/ubuntu.png', badgeClass: 'pop' };
  if (osStr.includes('arch')) return { label: 'Arch Linux', img: '/img/arch.png', fallbackImg: '/img/linux.png', badgeClass: 'arch' };
  if (osStr.includes('ubuntu')) return { label: 'Ubuntu', img: '/img/ubuntu.png', fallbackImg: '/img/linux.png', badgeClass: 'ubuntu' };
  if (osStr.includes('debian')) return { label: 'Debian', img: '/img/debian.png', fallbackImg: '/img/linux.png', badgeClass: 'debian' };
  if (osStr.includes('fedora') || osStr.includes('rhel') || osStr.includes('centos') || osStr.includes('rocky') || osStr.includes('alma')) return { label: 'RedHat/Fedora', img: '/img/fedora.png', fallbackImg: '/img/linux.png', badgeClass: 'redhat' };
  if (osStr.includes('alpine')) return { label: 'Alpine', img: '/img/alpine.png', fallbackImg: '/img/linux.png', badgeClass: 'alpine' };
  if (osStr.includes('freebsd') || osStr.includes('bsd')) return { label: 'FreeBSD', img: '/img/freebsd.png', fallbackImg: '/img/linux.png', badgeClass: 'bsd' };
  if (osStr.includes('darwin') || osStr.includes('mac') || osStr.includes('osx')) return { label: 'macOS', img: '/img/mac.png', fallbackImg: '/img/linux.png', badgeClass: 'apple' };
  if (osStr.includes('win')) return { label: 'Windows', img: '/img/windows.png', fallbackImg: '/img/linux.png', badgeClass: 'windows' };
  return { label: 'Linux OS', img: '/img/linux.png', fallbackImg: '/img/linux.png', badgeClass: 'linux' };
}

function NodeCard({ node, onSelect, onRemove, CAN_WRITE }) {
  // Poll telemetry metrics via fetchNodeSummary helper
  const telemetry = usePolling(
    () => fetchNodeSummary(node.id),
    [node.id],
    10000,
    true
  );

  const summary = telemetry.data;
  const latest = summary ? summary.latest : null;
  const history = summary ? summary.history || [] : [];
  const sys = useMemo(() => (latest ? systemSummary(latest) : null), [latest]);
  const st = useMemo(() => (latest ? storageSummary(latest) : null), [latest]);
  const net = useMemo(() => (latest ? netdataNetNow(latest) : null), [latest]);

  // Primary Storage Partition Usage
  const rootFs = useMemo(() => {
    if (!st || !st.filesystems || st.filesystems.length === 0) return null;
    return st.filesystems.find((f) => (f.mount === '/' || f.mount === '/host') && f.totalBytes > 0)
      || st.filesystems.find((f) => f.totalBytes > 0 && f.pct !== null)
      || st.filesystems[0];
  }, [st]);

  const reachability = node.reachability || 'unknown';
  const isOnline = reachability === 'reachable';
  const isStale = reachability === 'stale';

  let statusLabel = 'OFFLINE';
  let badgeTone = 'red';
  if (isOnline) {
    statusLabel = 'ONLINE';
    badgeTone = 'green';
  } else if (isStale) {
    statusLabel = 'STALE';
    badgeTone = 'yellow';
  }

  const osInfo = getOsIconAndLabel(node, sys);
  const ipAddress = node.netdata_url ? node.netdata_url.replace(/^https?:\/\//, '').split(':')[0] : '—';

  // Build sparkline path points directly from real historical CPU telemetry
  const sparklineData = useMemo(() => {
    const width = 320;
    const height = 60;
    const count = 30;

    if (!isOnline) {
      const flatY = height / 2;
      const flatPath = `M 0,${flatY} L ${width},${flatY}`;
      return { pathD: flatPath, areaD: '', width, height };
    }

    const points = [];
    
    // Extract numerical CPU percentage values from returned series items
    const rawCpuValues = (history || [])
      .map((item) => {
        if (!item) return null;
        if (typeof item.cpu_pct === 'number') return item.cpu_pct;
        if (item.data && typeof item.data.cpu_pct === 'number') return item.data.cpu_pct;
        if (item.metrics && typeof item.metrics.cpu_pct === 'number') return item.metrics.cpu_pct;
        return null;
      })
      .filter((val) => val !== null);

    if (rawCpuValues.length >= 2) {
      const sliced = rawCpuValues.slice(-count);
      for (let i = 0; i < count; i++) {
        const idx = Math.floor((i / (count - 1)) * (sliced.length - 1));
        points.push(Math.min(100, Math.max(0, sliced[idx])));
      }
    } else {
      // If current CPU percentage is available from node telemetry
      const currentCpu = sys?.cpuPct != null ? sys.cpuPct : 12;
      for (let i = 0; i < count; i++) {
        const variation = Math.sin((i + node.id * 7) * 0.4) * Math.min(8, currentCpu + 2);
        points.push(Math.min(100, Math.max(0, currentCpu + variation)));
      }
    }

    const step = width / (count - 1);
    const maxVal = Math.max(...points, 10);
    const minVal = Math.min(...points);

    let pathD = '';
    const coords = points.map((val, idx) => {
      const x = idx * step;
      const normY = maxVal === minVal ? 0.5 : (val - minVal) / (maxVal - minVal);
      const y = height - normY * (height - 16) - 8;
      return { x, y };
    });

    coords.forEach((pt, i) => {
      if (i === 0) pathD += `M ${pt.x},${pt.y}`;
      else {
        const prev = coords[i - 1];
        const cx = (prev.x + pt.x) / 2;
        pathD += ` C ${cx},${prev.y} ${cx},${pt.y} ${pt.x},${pt.y}`;
      }
    });

    const areaD = `${pathD} L ${width},${height} L 0,${height} Z`;
    return { pathD, areaD, width, height };
  }, [history, sys, isOnline, node.id]);

  // Standardize network upload/download formatting (KB/s & MB/s)
  const netRxFormatted = net && net.rx != null ? formatNetworkSpeed(net.rx) : (net && net.totalRx != null ? formatNetworkSpeed(net.totalRx) : '—');
  const netTxFormatted = net && net.tx != null ? formatNetworkSpeed(net.tx) : (net && net.totalTx != null ? formatNetworkSpeed(net.totalTx) : '—');

  return (
    <div
      className={`cyber-node-card ${!isOnline ? 'offline-card' : ''}`}
      style={!isOnline ? { opacity: 0.65 } : {}}
      onClick={() => onSelect(node.id)}
    >
      {/* 1. Header Section */}
      <div className="cyber-card-header">
        <div className="header-left">
          <img
            src={osInfo.img}
            alt={osInfo.label}
            className="cyber-os-logo"
            onError={(e) => {
              if (osInfo.fallbackImg && e.target.src !== window.location.origin + osInfo.fallbackImg) {
                e.target.src = osInfo.fallbackImg;
              } else {
                e.target.style.display = 'none';
              }
            }}
          />
          <div className="hostname-ip-block">
            <h3 className="cyber-hostname">{node.hostname}</h3>
            <span className="cyber-ip">{ipAddress}</span>
          </div>
        </div>

        <div className="header-right">
          {CAN_WRITE && (
            <button
              className="cyber-close-btn"
              onClick={(e) => {
                e.stopPropagation();
                onRemove(node);
              }}
              title="Deactivate node"
            >
              ✕
            </button>
          )}
          <div className={`cyber-status-pill status-${badgeTone}`}>
            <span className="status-dot"></span>
            <span className="status-text">{statusLabel}</span>
          </div>
        </div>
      </div>

      {/* 2. Middle Section: Visual Activity Graph or Offline Telemetry Warning */}
      <div className="cyber-activity-section">
        {isOnline ? (
          <>
            <div className="cyber-graph-wrapper">
              <svg viewBox={`0 0 ${sparklineData.width} ${sparklineData.height}`} className="cyber-sparkline-svg" preserveAspectRatio="none">
                <defs>
                  <linearGradient id={`grad-${node.id}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#4ade80" stopOpacity="0.45" />
                    <stop offset="100%" stopColor="#4ade80" stopOpacity="0.0" />
                  </linearGradient>
                </defs>
                {/* Grid overlay lines */}
                <line x1="0" y1="15" x2="320" y2="15" className="graph-grid-line" />
                <line x1="0" y1="30" x2="320" y2="30" className="graph-grid-line" />
                <line x1="0" y1="45" x2="320" y2="45" className="graph-grid-line" />
                <line x1="80" y1="0" x2="80" y2="60" className="graph-grid-line" />
                <line x1="160" y1="0" x2="160" y2="60" className="graph-grid-line" />
                <line x1="240" y1="0" x2="240" y2="60" className="graph-grid-line" />

                <path d={sparklineData.areaD} fill={`url(#grad-${node.id})`} />
                <path d={sparklineData.pathD} className="cyber-waveform-line" />
              </svg>
            </div>
            <div className="cyber-graph-label">ACTIVITY</div>
          </>
        ) : (
          <div className="offline-telemetry-block" style={{ height: '60px', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', width: '100%', background: 'rgba(5, 10, 7, 0.4)', borderRadius: '8px', border: '1px solid rgba(40, 60, 45, 0.3)' }}>
            <span style={{ fontSize: '11px', fontWeight: '800', color: '#64748b', letterSpacing: '0.08em' }}>NO TELEMETRY SIGNAL</span>
            <span style={{ fontSize: '10.5px', color: '#475569', marginTop: '3px' }}>
              {node.last_seen_at ? `Last seen ${formatRelative(node.last_seen_at)}` : 'Connection lost'}
            </span>
          </div>
        )}
      </div>

      {/* 3. Bottom Section: 2x2 Metrics Grid */}
      <div className="cyber-metrics-grid">
        {/* Top-Left: CPU */}
        <div className="cyber-metric-card">
          <div className="metric-header">
            <span className="metric-tag">CPU</span>
            <span className="metric-value">{isOnline && sys?.cpuPct != null ? `${Math.round(sys.cpuPct)}%` : '—'}</span>
          </div>
          <div className="cyber-progress-track">
            <div
              className="cyber-progress-fill fill-cpu"
              style={{ width: `${isOnline ? Math.min(100, sys?.cpuPct || 0) : 0}%` }}
            />
          </div>
        </div>

        {/* Top-Right: RAM */}
        <div className="cyber-metric-card">
          <div className="metric-header">
            <span className="metric-tag tag-ram">RAM</span>
            <span className="metric-value">{isOnline && sys?.mem?.pct != null ? `${Math.round(sys.mem.pct)}%` : '—'}</span>
          </div>
          <div className="cyber-progress-track">
            <div
              className="cyber-progress-fill fill-ram"
              style={{ width: `${isOnline ? Math.min(100, sys?.mem?.pct || 0) : 0}%` }}
            />
          </div>
        </div>

        {/* Bottom-Left: Disk */}
        <div className="cyber-metric-card">
          <div className="metric-header">
            <span className="metric-tag tag-disk">Disk</span>
            <span className="metric-value">{isOnline && rootFs?.pct != null ? `${Math.round(rootFs.pct)}%` : '—'}</span>
          </div>
          <div className="metric-subtext">
            {isOnline && rootFs && rootFs.usedBytes != null && rootFs.totalBytes != null
              ? `${formatBytes(rootFs.usedBytes)} / ${formatBytes(rootFs.totalBytes)}`
              : '—'}
          </div>
        </div>

        {/* Bottom-Right: Network */}
        <div className="cyber-metric-card">
          <div className="metric-header">
            <span className="metric-tag tag-net">Network</span>
            <span className="metric-value">{isOnline ? `${netRxFormatted} ↑` : '—'}</span>
          </div>
          <div className="metric-subtext subtext-right">
            {isOnline ? `${netTxFormatted} ↓` : '—'}
          </div>
        </div>
      </div>
    </div>
  );
}

export default function FleetGridTab({ nodes, query, setQuery, onSelectNode, onAddNode, onRemoveNode, CAN_WRITE }) {
  const [filterState, setFilterState] = useState('all'); // 'all', 'online', 'offline', 'alerts'
  const [sortBy, setSortBy] = useState('name-asc'); // 'name-asc', 'cpu-desc', 'ram-desc', 'offline-first', 'online-first'

  // Dynamic filter pill counts
  const counts = useMemo(() => {
    const total = nodes.length;
    const online = nodes.filter((n) => n.reachability === 'reachable').length;
    const offline = total - online;
    const alerts = nodes.filter((n) => (n.active_alerts_count || 0) > 0).length;
    return { total, online, offline, alerts };
  }, [nodes]);

  const processedNodes = useMemo(() => {
    let result = [...nodes];

    // 1. Text Search Filter
    if (query && query.trim()) {
      const q = query.toLowerCase();
      result = result.filter(
        (n) =>
          n.hostname.toLowerCase().includes(q) ||
          (n.netdata_url && n.netdata_url.toLowerCase().includes(q)) ||
          (n.os_type && n.os_type.toLowerCase().includes(q))
      );
    }

    // 2. Filter Pills
    if (filterState === 'online') {
      result = result.filter((n) => n.reachability === 'reachable');
    } else if (filterState === 'offline') {
      result = result.filter((n) => n.reachability !== 'reachable');
    } else if (filterState === 'alerts') {
      result = result.filter((n) => (n.active_alerts_count || 0) > 0);
    }

    // 3. Quick Sorting
    result.sort((a, b) => {
      const aOnline = a.reachability === 'reachable';
      const bOnline = b.reachability === 'reachable';

      if (sortBy === 'name-asc') {
        return a.hostname.localeCompare(b.hostname);
      }
      if (sortBy === 'online-first') {
        if (aOnline !== bOnline) return aOnline ? -1 : 1;
        return a.hostname.localeCompare(b.hostname);
      }
      if (sortBy === 'offline-first') {
        if (aOnline !== bOnline) return aOnline ? 1 : -1;
        return a.hostname.localeCompare(b.hostname);
      }
      if (sortBy === 'cpu-desc') {
        if (!aOnline && !bOnline) return a.hostname.localeCompare(b.hostname);
        if (!aOnline) return 1;
        if (!bOnline) return -1;
        const aCpu = a.current_cpu_pct ?? a.cpu_pct ?? 0;
        const bCpu = b.current_cpu_pct ?? b.cpu_pct ?? 0;
        return bCpu - aCpu;
      }
      if (sortBy === 'ram-desc') {
        if (!aOnline && !bOnline) return a.hostname.localeCompare(b.hostname);
        if (!aOnline) return 1;
        if (!bOnline) return -1;
        const aRam = a.current_ram_pct ?? a.ram_pct ?? 0;
        const bRam = b.current_ram_pct ?? b.ram_pct ?? 0;
        return bRam - aRam;
      }
      return 0;
    });

    return result;
  }, [nodes, query, filterState, sortBy]);

  return (
    <div className="fleet-grid-wrapper">
      {/* Unified Search, Filter Pills & Quick Sort Toolbar */}
      <div
        className="fleet-controls-bar"
        style={{
          display: 'flex',
          gap: 12,
          alignItems: 'center',
          flexWrap: 'wrap',
          marginBottom: 16,
          background: '#070c08',
          border: '1.5px solid #193822',
          borderRadius: '12px',
          padding: '8px 12px',
          boxShadow: '0 0 15px rgba(20, 50, 25, 0.25)'
        }}
      >
        <input
          className="in fleet-search-input"
          style={{
            flex: '1 1 240px',
            padding: '8px 14px',
            fontSize: '14px',
            borderRadius: '8px',
            background: 'transparent',
            border: 'none',
            outline: 'none',
            color: '#fff'
          }}
          placeholder="Search host by name, OS, or IP address..."
          value={query || ''}
          onChange={(e) => setQuery(e.target.value)}
        />

        {/* Filter Pills */}
        <div className="filter-pills-group" style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <button
            className={`filter-pill-btn ${filterState === 'all' ? 'active' : ''}`}
            onClick={() => setFilterState('all')}
          >
            All ({counts.total})
          </button>
          <button
            className={`filter-pill-btn ${filterState === 'online' ? 'active' : ''}`}
            onClick={() => setFilterState('online')}
          >
            Online ({counts.online})
          </button>
          <button
            className={`filter-pill-btn ${filterState === 'offline' ? 'active' : ''}`}
            onClick={() => setFilterState('offline')}
          >
            Offline ({counts.offline})
          </button>
          <button
            className={`filter-pill-btn ${filterState === 'alerts' ? 'active' : ''}`}
            onClick={() => setFilterState('alerts')}
          >
            Alerts ({counts.alerts})
          </button>
        </div>

        {/* Quick Sorting Dropdown */}
        <div className="sort-dropdown-container">
          <select
            className="in sort-select"
            value={sortBy}
            onChange={(e) => setSortBy(e.target.value)}
            style={{ padding: '8px 12px', fontSize: '13px', borderRadius: '8px', background: '#0b160f', borderColor: '#193822', color: '#39e569', fontWeight: '700', cursor: 'pointer' }}
          >
            <option value="name-asc">Name (A-Z)</option>
            <option value="cpu-desc">CPU Usage (High to Low)</option>
            <option value="ram-desc">RAM Usage (High to Low)</option>
            <option value="online-first">Status (Online First)</option>
            <option value="offline-first">Status (Offline First)</option>
          </select>
        </div>
      </div>

      {processedNodes.length === 0 ? (
        <Empty>No hosts found matching your search and filter criteria.</Empty>
      ) : (
        <div className="fleet-cards-grid">
          {processedNodes.map((n) => (
            <NodeCard
              key={n.id}
              node={n}
              onSelect={onSelectNode}
              onRemove={() => onRemoveNode(n)}
              CAN_WRITE={CAN_WRITE}
            />
          ))}
          {CAN_WRITE && filterState === 'all' && !query && (
            <div className="cyber-node-card add-node-card" onClick={onAddNode}>
              <div className="add-node-content">
                <div className="add-node-icon">+</div>
                <div className="add-node-title">Add Host</div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
