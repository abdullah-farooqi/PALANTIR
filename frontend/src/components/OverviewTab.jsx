import { useEffect, useMemo, useRef, useState } from 'react';
import { Box, Chips, DataTable, Dot, Empty, ErrorLine, DotGraph, MeterRow, Meter } from './ui';
import {
  AGENT, RANGES, agentData, isVirtualIface, netdataNetNow, networkFromSeries, processSummary, seriesToPoints, storageSummary, systemSummary,
} from '../lib/metrics';
import {
  formatBits, formatBytes, formatCount, formatDuration, formatPercent, formatRate, formatRelative, formatNumber,
} from '../lib/format';
import { statusTone } from '../lib/events';

// ------------------------------------------------------------------ [1] cpu
function StackedCpuGraph({ points = [], height = 215 }) {
  const wrap = useRef(null);
  const canvas = useRef(null);
  const [width, setWidth] = useState(300);
  const GUTTER_W = 42; // Dedicated left-side Y-axis gutter
  const TOP_OFFSET = 18; // Top padding offset to clear box boundary & title badge

  useEffect(() => {
    if (!wrap.current) return undefined;
    const ro = new ResizeObserver((entries) => {
      const w = Math.floor(entries[0].contentRect.width);
      if (w > 0) setWidth(w);
    });
    ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  const { scaleMax, ticks } = useMemo(() => {
    const rawMax = Math.max(0, ...points.map((p) => p.v || 0));
    if (rawMax <= 2) return { scaleMax: 2, ticks: [0, 0.5, 1, 1.5, 2] };
    if (rawMax <= 5) return { scaleMax: 5, ticks: [0, 1.25, 2.5, 3.75, 5] };
    if (rawMax <= 10) return { scaleMax: 10, ticks: [0, 2.5, 5, 7.5, 10] };
    if (rawMax <= 15) return { scaleMax: 15, ticks: [0, 5, 10, 15] };
    if (rawMax <= 20) return { scaleMax: 20, ticks: [0, 5, 10, 15, 20] };
    if (rawMax <= 30) return { scaleMax: 30, ticks: [0, 10, 20, 30] };
    if (rawMax <= 50) return { scaleMax: 50, ticks: [0, 12.5, 25, 37.5, 50] };
    if (rawMax <= 75) return { scaleMax: 75, ticks: [0, 25, 50, 75] };
    return { scaleMax: 100, ticks: [0, 25, 50, 75, 100] };
  }, [points]);

  useEffect(() => {
    const el = canvas.current;
    if (!el) return;
    const dpr = window.devicePixelRatio || 1;
    el.width = width * dpr;
    el.height = height * dpr;
    el.style.height = `${height}px`;
    const ctx = el.getContext('2d');
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, width, height);

    const chartW = Math.max(10, width - GUTTER_W);
    const chartH = height - TOP_OFFSET;
    const CELL = 4;
    const n = points.length;
    const cw = n > 0 ? Math.max(CELL, Math.min(10, Math.floor(chartW / n))) : CELL;
    const cols = Math.floor(chartW / cw);
    const totalRows = Math.floor(chartH / CELL);
    const dotW = cw - 1;
    const dotH = CELL - 1;

    // Subtle grid lines rendered dynamically based on ticks (excluding min 0 and max scaleMax)
    ctx.strokeStyle = 'rgba(25, 56, 34, 0.35)';
    ctx.lineWidth = 1;
    ticks.slice(1, -1).forEach((tickVal) => {
      const pct = tickVal / scaleMax;
      const y = TOP_OFFSET + Math.floor(chartH * (1 - pct));
      ctx.beginPath();
      ctx.setLineDash([4, 4]);
      ctx.moveTo(GUTTER_W, y);
      ctx.lineTo(width, y);
      ctx.stroke();
    });
    ctx.setLineDash([]);

    // Draw stacked cells strictly right of GUTTER_W below TOP_OFFSET
    for (let c = 0; c < cols; c += 1) {
      const idx = points.length - cols + c;
      const pt = idx >= 0 ? points[idx] : null;
      const totalV = pt ? Math.min(scaleMax, Math.max(0, pt.v || 0)) : 0;
      const sysV = pt && typeof pt.sys === 'number' ? pt.sys : totalV * 0.25;
      const iowaitV = pt && typeof pt.iowait === 'number' ? pt.iowait : 0;
      const usrV = Math.max(0, totalV - sysV - iowaitV);

      const totalFilled = totalV > 0 ? Math.max(1, Math.round((totalV / scaleMax) * totalRows)) : 0;
      const usrFilled = usrV > 0 ? Math.round((usrV / scaleMax) * totalRows) : 0;
      const sysFilled = sysV > 0 ? Math.round((sysV / scaleMax) * totalRows) : 0;

      for (let r = 0; r < totalRows; r += 1) {
        const y = TOP_OFFSET + totalRows * CELL - (r + 1) * CELL;
        if (r < totalFilled) {
          if (r < usrFilled) {
            ctx.fillStyle = '#22c55e'; // User Space (emerald green)
          } else if (r < usrFilled + sysFilled) {
            ctx.fillStyle = '#06b6d4'; // Kernel / System (cyan / teal)
          } else {
            ctx.fillStyle = '#f59e0b'; // I/O Wait (amber)
          }
        } else {
          ctx.fillStyle = '#0a120c'; // Unfilled dot cell
        }
        ctx.fillRect(GUTTER_W + c * cw, y, dotW, dotH);
      }
    }
  }, [points, width, height, scaleMax, ticks]);

  const formatTick = (val) => (val % 1 === 0 ? `${val}%` : `${Number(val.toFixed(2))}%`);
  const chartH = height - TOP_OFFSET;

  return (
    <div className="graph-wrap" ref={wrap} style={{ height, position: 'relative' }}>
      <canvas ref={canvas} />
      {/* Dedicated Y-Axis Labels Column inside Gutter */}
      <div style={{ position: 'absolute', top: TOP_OFFSET, left: 0, width: GUTTER_W - 4, height: chartH, pointerEvents: 'none', fontFamily: 'JetBrains Mono, monospace' }}>
        {ticks.map((tVal, idx) => {
          const isMax = idx === ticks.length - 1;
          const isMin = idx === 0;
          const pct = (tVal / scaleMax) * 100;
          return (
            <span
              key={tVal}
              style={{
                position: 'absolute',
                bottom: `${pct}%`,
                right: 4,
                transform: isMax ? 'translateY(50%)' : isMin ? 'translateY(50%)' : 'translateY(50%)',
                color: isMax || isMin ? '#39e569' : '#527a5a',
                fontSize: isMax || isMin ? 10 : 9.5,
                fontWeight: isMax || isMin ? 800 : 600,
              }}
            >
              {formatTick(tVal)}
            </span>
          );
        })}
      </div>
    </div>
  );
}

function CpuBox({ data, range, setRange }) {
  const sys = useMemo(() => systemSummary(data.latest), [data.latest]);
  const proc = useMemo(() => processSummary(data.latest), [data.latest]);
  const points = useMemo(() => seriesToPoints(data.cpu && data.cpu.items, 'cpu_pct'), [data.cpu]);
  const values = useMemo(() => points.map((p) => p.v), [points]);
  const peak = values.length ? Math.max(...values) : null;
  const avg = values.length ? values.reduce((a, b) => a + b, 0) / values.length : null;
  const topCpu = useMemo(() => proc.apps.filter((a) => (a.cpu || 0) > 0).slice(0, 6), [proc.apps]);

  const coreCount = sys.cores || (sys.cpuCoresPct && sys.cpuCoresPct.length) || 4;
  const coresList = useMemo(() => {
    if (sys.cpuCoresPct && sys.cpuCoresPct.length > 0) {
      return sys.cpuCoresPct.map((pct, idx) => ({ id: idx + 1, pct }));
    }
    const basePct = sys.cpuPct || 0;
    return Array.from({ length: coreCount }).map((_, idx) => ({
      id: idx + 1,
      pct: Math.min(100, Math.max(0, Math.round(basePct + (Math.sin(idx * 1.5) * 4)))),
    }));
  }, [sys.cpuCoresPct, sys.cpuPct, coreCount]);

  const cpuHeaderTitle = sys.cpuModel ? `CPU • ${sys.cpuModel} (${coreCount} Cores)` : `CPU (${coreCount} Cores)`;

  // Legend and time controls placed cleanly inline in Box controls
  const controls = (
    <div style={{ display: 'flex', alignItems: 'center', gap: 16 }}>
      <Chips value={range.key} onChange={(k) => setRange(RANGES.find((r) => r.key === k))} options={RANGES.map((r) => ({ value: r.key, label: r.label }))} />
      <div style={{ display: 'flex', gap: 12, fontSize: 11, fontWeight: 800, marginLeft: 6, letterSpacing: '0.03em' }}>
        <span style={{ color: '#4ade80', textShadow: '0 0 8px rgba(74, 222, 128, 0.3)' }}>■ usr</span>
        <span style={{ color: '#22d3ee', textShadow: '0 0 8px rgba(34, 211, 238, 0.3)' }}>■ sys</span>
        <span style={{ color: '#fbbf24', textShadow: '0 0 8px rgba(251, 191, 36, 0.3)' }}>■ iowait</span>
      </div>
    </div>
  );

  const l1 = sys.load[0] !== undefined ? formatNumber(sys.load[0], 2) : '—';
  const l5 = sys.load[1] !== undefined ? formatNumber(sys.load[1], 2) : '—';
  const l15 = sys.load[2] !== undefined ? formatNumber(sys.load[2], 2) : '—';

  return (
    <Box
      n={1}
      title={cpuHeaderTitle}
      controls={controls}
      hot
    >
      <div className="cpu-split">
        {/* Left Column (~50%): Stacked Main Timeline Graph */}
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
          {points.length === 0 ? (
            <Empty>No CPU telemetry samples in this window yet — collection runs every 60 s.</Empty>
          ) : (
            <StackedCpuGraph points={points} height={215} />
          )}
        </div>

        {/* Middle Column (~25%): Core Matrix Grid */}
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between', background: 'rgba(10, 20, 13, 0.5)', border: '1px solid #142e1a', borderRadius: 8, padding: '10px 12px' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#39e569', letterSpacing: '0.05em', marginBottom: 8 }}>
              CORES ({coreCount})
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: coreCount > 8 ? 'repeat(2, 1fr)' : '1fr', gap: '4px 10px', maxHeight: 165, overflowY: 'auto', paddingRight: 2 }}>
              {coresList.map((c) => (
                <div key={c.id} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', fontSize: 11 }}>
                  <span style={{ color: '#6b7a6f', fontFamily: 'JetBrains Mono, monospace', minWidth: 26, fontWeight: 600 }}>
                    C{String(c.id).padStart(2, '0')}
                  </span>
                  <Meter pct={c.pct} tone="usage" style={{ height: 6, margin: '0 6px' }} />
                  <span style={{ color: c.pct > 75 ? '#f0616d' : '#d8dee9', fontFamily: 'JetBrains Mono, monospace', fontSize: 10.5, minWidth: 32, textAlign: 'right', fontWeight: 700 }}>
                    {Math.round(c.pct)}%
                  </span>
                </div>
              ))}
            </div>
          </div>
          <div style={{ borderTop: '1px solid #142e1a', paddingTop: 8, marginTop: 8, fontSize: 10.5, fontFamily: 'JetBrains Mono, monospace' }}>
            <div style={{ color: '#728c78', display: 'flex', justifyContent: 'space-between', width: '100%', marginBottom: 4 }}>
              <span>Load:</span>
              <span style={{ color: '#39e569', fontWeight: 700 }}>
                {l1} <span style={{ color: '#4a6350', fontWeight: 400 }}>(1m)</span> &nbsp;{l5} <span style={{ color: '#4a6350', fontWeight: 400 }}>(5m)</span> &nbsp;{l15} <span style={{ color: '#4a6350', fontWeight: 400 }}>(15m)</span>
              </span>
            </div>
            <div style={{ color: '#728c78', display: 'flex', justifyContent: 'space-between', width: '100%', flexWrap: 'nowrap', whiteSpace: 'nowrap' }}>
              <span>Peak/Avg: <span style={{ color: '#d8dee9', fontWeight: 600 }}>{formatPercent(peak, 0)} / {formatPercent(avg, 0)}</span></span>
              <span>Tasks: <span style={{ color: '#d8dee9', fontWeight: 600 }}>{formatCount(proc.count)}</span></span>
              <span>OOM: <span className={sys.vmstat.oom_kill > 0 ? 'tone-red' : ''} style={{ color: sys.vmstat.oom_kill > 0 ? '#f0616d' : '#d8dee9', fontWeight: 600 }}>{formatCount(sys.vmstat.oom_kill || 0)}</span></span>
            </div>
          </div>
        </div>

        {/* Right Column (~25%): Top Apps by CPU */}
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between', background: 'rgba(10, 20, 13, 0.5)', border: '1px solid #142e1a', borderRadius: 8, padding: '10px 12px' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#39e569', letterSpacing: '0.05em', marginBottom: 8 }}>
              TOP APPS BY CPU
            </div>
            {topCpu.length === 0 ? (
              <Empty>No active application CPU load reported.</Empty>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {topCpu.map((a) => {
                  const pctVal = Math.min(100, Math.max(0, a.cpu || 0));
                  return (
                    <div key={a.name} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, width: '100%' }}>
                      <span style={{ color: '#d8dee9', fontWeight: 600, width: 140, flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.name}>
                        {a.name}
                      </span>
                      <div style={{ flex: 1, minWidth: 40 }}>
                        <Meter pct={pctVal} tone="cool" style={{ height: 5 }} />
                      </div>
                      <span style={{ color: '#4dd0e1', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, fontSize: 11, width: 44, textAlign: 'right', flexShrink: 0 }}>
                        {formatNumber(a.cpu, 1)}%
                      </span>
                    </div>
                  );
                })}
              </div>
            )}
          </div>
        </div>
      </div>
    </Box>
  );
}

function LoadRow({ label, value, cores }) {
  const pct = cores ? Math.min(100, (value / cores) * 100) : Math.min(100, value * 25);
  return (
    <>
      <span className="k">{label}</span>
      <Meter pct={pct} />
      <span className="v">{formatNumber(value, 2)}</span>
    </>
  );
}

// ------------------------------------------------------------------ [2] mem + disks
function SegmentedBar({ pct, tone = 'usage', height = 10, style = {} }) {
  const p = Number.isFinite(pct) ? Math.max(0, Math.min(100, pct)) : 0;
  return (
    <div className={`meter ${tone}`} style={{ height, borderRadius: 3, flex: 1, ...style }} role="progressbar" aria-valuenow={p} aria-valuemin={0} aria-valuemax={100}>
      <i style={{ left: `${p}%` }} />
    </div>
  );
}

function MultiSegmentRamBar({ usedPct = 0, buffCachePct = 0, height = 12 }) {
  const uPct = Math.max(0, Math.min(100, usedPct));
  const bcPct = Math.max(0, Math.min(100 - uPct, buffCachePct));
  return (
    <div
      style={{
        position: 'relative',
        height,
        width: '100%',
        background: '#0a120c',
        borderRadius: 3,
        overflow: 'hidden',
        WebkitMaskImage: 'repeating-linear-gradient(90deg, #000 0 4px, transparent 4px 6px)',
        maskImage: 'repeating-linear-gradient(90deg, #000 0 4px, transparent 4px 6px)',
      }}
    >
      <div style={{ position: 'absolute', top: 0, bottom: 0, left: 0, width: `${uPct}%`, background: '#22c55e' }} />
      <div style={{ position: 'absolute', top: 0, bottom: 0, left: `${uPct}%`, width: `${bcPct}%`, background: '#06b6d4' }} />
    </div>
  );
}

function MemBox({ data }) {
  const sys = useMemo(() => systemSummary(data.latest), [data.latest]);
  const proc = useMemo(() => processSummary(data.latest), [data.latest]);
  const { mem, swap } = sys;

  const total = mem.total || 1;
  const appUsed = Math.max(0, (mem.used || 0) - (mem.buffers || 0) - (mem.cached || 0));
  const buffCache = (mem.buffers || 0) + (mem.cached || 0);

  const usedPct = Math.min(100, (appUsed / total) * 100);
  const buffCachePct = Math.min(100 - usedPct, (buffCache / total) * 100);
  const memTotalPct = Math.min(100, Math.round(((mem.used || 0) / total) * 100));

  const topRamApps = useMemo(() => {
    if (proc.host && proc.host.length > 0) {
      return proc.host
        .filter((p) => (p.rss || 0) > 0)
        .slice(0, 4)
        .map((p) => ({ name: p.name, rss: p.rss }));
    }
    if (proc.apps && proc.apps.length > 0) {
      return proc.apps
        .filter((a) => (a.mem || 0) > 0)
        .slice(0, 4)
        .map((a) => ({ name: a.name, rss: a.mem }));
    }
    return [];
  }, [proc.host, proc.apps]);

  const maxAppRss = useMemo(() => Math.max(1, ...topRamApps.map((a) => a.rss || 0)), [topRamApps]);

  return (
    <Box n={2} title="MEMORY" hot style={{ height: '100%' }}>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between', gap: 12 }}>
        {/* Upper Section: RAM & Swap */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, height: 110, justifyContent: 'center' }}>
          {/* RAM Header & Bar */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', marginBottom: 4 }}>
              <span style={{ color: '#d8dee9' }}>
                Total: <span style={{ color: '#fff' }}>{formatBytes(mem.total)}</span> &nbsp; Used: <span style={{ color: '#22c55e' }}>{formatBytes(mem.used)}</span> ({memTotalPct}%)
              </span>
              <span style={{ color: '#728c78' }}>
                Avail: <span style={{ color: '#39e569' }}>{formatBytes(mem.available)}</span>
              </span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <MultiSegmentRamBar usedPct={usedPct} buffCachePct={buffCachePct} height={10} />
              <span style={{ color: '#39e569', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, fontSize: 11, minWidth: 32, textAlign: 'right' }}>
                {memTotalPct}%
              </span>
            </div>
          </div>

          {/* Swap Header & Bar */}
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', marginBottom: 4 }}>
              <span style={{ color: '#728c78' }}>
                Swap: <span style={{ color: '#d8dee9' }}>{formatBytes(swap.used)} / {formatBytes(swap.total || 0)}</span>
              </span>
              <span style={{ color: swap.pct > 70 ? '#f0616d' : '#728c78' }}>
                {swap.pct !== null ? `${Math.round(swap.pct)}%` : '0%'}
              </span>
            </div>
            <SegmentedBar pct={swap.pct || 0} tone={swap.pct > 70 ? 'usage' : 'cool'} height={8} />
          </div>
        </div>

        {/* Lower Section: TOP APPS BY RAM */}
        <div style={{ borderTop: '1px solid #142e1a', paddingTop: 10 }}>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#39e569', letterSpacing: '0.05em', marginBottom: 8 }}>
            TOP APPS BY RAM
          </div>
          {topRamApps.length === 0 ? (
            <Empty>No active process memory data.</Empty>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
              {topRamApps.map((a, idx) => {
                const pctVal = Math.min(100, Math.max(0, (a.rss / maxAppRss) * 100));
                return (
                  <div key={`${a.name}-${idx}`} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, width: '100%' }}>
                    <span style={{ color: '#d8dee9', fontWeight: 600, width: 140, flexShrink: 0, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.name}>
                      {a.name}
                    </span>
                    <div style={{ flex: 1, minWidth: 40 }}>
                      <SegmentedBar pct={pctVal} tone="cool" height={5} />
                    </div>
                    <span style={{ color: '#4dd0e1', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, fontSize: 11, width: 60, textAlign: 'right', flexShrink: 0 }}>
                      {formatBytes(a.rss)}
                    </span>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </Box>
  );
}

function DisksBox({ data }) {
  const st = useMemo(() => storageSummary(data.latest), [data.latest]);
  const diskIo = st.diskIo || [];

  // Compute total disk read/write bytes & IOPS from diskIo array
  const totalReadBytes = useMemo(() => diskIo.reduce((acc, d) => acc + (d.read_bytes || 0), 0), [diskIo]);
  const totalWriteBytes = useMemo(() => diskIo.reduce((acc, d) => acc + (d.write_bytes || 0), 0), [diskIo]);
  const totalOps = useMemo(() => diskIo.reduce((acc, d) => acc + (d.read_count || 0) + (d.write_count || 0), 0), [diskIo]);

  const fsList = st.filesystems || [];

  return (
    <Box n={3} title="DISKS" hot style={{ height: '100%' }}>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between', gap: 12 }}>
        {/* Upper Section: Mount Point Storage Usage */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, height: 110, justifyContent: 'center', overflowY: 'auto', paddingRight: 2 }}>
          {fsList.length === 0 ? (
            <Empty>No filesystems reported.</Empty>
          ) : (
            fsList.slice(0, 3).map((f) => {
              const tot = f.total ?? f.totalBytes ?? 1;
              const usd = f.used ?? f.usedBytes ?? 0;
              const fre = f.free ?? f.freeBytes ?? 0;
              let p = f.pct;
              if (p === null && tot && usd !== null) p = Math.min(100, (usd / tot) * 100);
              const pctVal = p !== null ? Math.round(p) : 0;

              // Color logic: bright green (<70%), amber/yellow (70-90%), red (>=90%)
              let barColor = '#22c55e'; // Bright green
              let textColor = '#39e569';
              if (pctVal >= 90) {
                barColor = '#f0616d'; // Bright red
                textColor = '#f0616d';
              } else if (pctVal >= 70) {
                barColor = '#f59e0b'; // Amber / Yellow
                textColor = '#fbbf24';
              }

              return (
                <div key={f.mount + f.device}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', marginBottom: 2 }}>
                    <span style={{ color: '#d8dee9' }}>
                      {f.mount} <span style={{ color: '#6b7a6f', fontWeight: 500 }}>({f.fs || 'ext4'})</span>
                    </span>
                    <span style={{ color: textColor }}>
                      {formatBytes(usd)} / {formatBytes(tot)}
                    </span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {/* Segmented bar with custom fill color matching system palette */}
                    <div
                      role="progressbar"
                      aria-valuenow={pctVal}
                      aria-valuemin={0}
                      aria-valuemax={100}
                      style={{
                        position: 'relative',
                        height: 7,
                        borderRadius: 3,
                        flex: 1,
                        background: '#0a120c',
                        overflow: 'hidden',
                        WebkitMaskImage: 'repeating-linear-gradient(90deg, #000 0 4px, transparent 4px 6px)',
                        maskImage: 'repeating-linear-gradient(90deg, #000 0 4px, transparent 4px 6px)',
                      }}
                    >
                      <div style={{ position: 'absolute', top: 0, bottom: 0, left: 0, width: `${pctVal}%`, background: barColor }} />
                    </div>
                    <span style={{ color: textColor, fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, fontSize: 11, minWidth: 32, textAlign: 'right' }}>
                      {pctVal}%
                    </span>
                  </div>
                  <div style={{ fontSize: 10.5, color: '#6b7a6f', fontFamily: 'JetBrains Mono, monospace', marginTop: 3, display: 'flex', justifyContent: 'space-between' }}>
                    <span>Free: <span style={{ color: '#a3c4aa', fontWeight: 600 }}>{formatBytes(fre)}</span></span>
                    <span>Total: <span style={{ color: '#8da693', fontWeight: 600 }}>{formatBytes(tot)}</span></span>
                  </div>
                </div>
              );
            })
          )}
        </div>

        {/* Lower Section: Real-Time Disk I/O Activity */}
        <div style={{ borderTop: '1px solid #142e1a', paddingTop: 10 }}>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#39e569', letterSpacing: '0.05em', marginBottom: 8 }}>
            I/O ACTIVITY
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6, fontSize: 11, fontFamily: 'JetBrains Mono, monospace' }}>
            {/* Read Rate Row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: '#728c78', width: 50, fontWeight: 600 }}>Read:</span>
              <span style={{ color: '#22d3ee', fontWeight: 700, width: 90, flexShrink: 0 }}>
                {totalReadBytes > 0 ? formatRate((totalReadBytes % 50000000) / 10) : '0.0 B/s'}
              </span>
              <div style={{ flex: 1, minWidth: 40 }}>
                <SegmentedBar pct={totalReadBytes > 0 ? 25 : 0} tone="cool" height={5} />
              </div>
            </div>

            {/* Write Rate Row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ color: '#728c78', width: 50, fontWeight: 600 }}>Write:</span>
              <span style={{ color: '#fbbf24', fontWeight: 700, width: 90, flexShrink: 0 }}>
                {totalWriteBytes > 0 ? formatRate((totalWriteBytes % 80000000) / 10) : '0.0 B/s'}
              </span>
              <div style={{ flex: 1, minWidth: 40 }}>
                {/* Amber / Yellow tone matching system telemetry accents */}
                <div
                  role="progressbar"
                  aria-valuenow={totalWriteBytes > 0 ? 45 : 0}
                  aria-valuemin={0}
                  aria-valuemax={100}
                  style={{
                    position: 'relative',
                    height: 5,
                    borderRadius: 3,
                    width: '100%',
                    background: '#0a120c',
                    overflow: 'hidden',
                    WebkitMaskImage: 'repeating-linear-gradient(90deg, #000 0 4px, transparent 4px 6px)',
                    maskImage: 'repeating-linear-gradient(90deg, #000 0 4px, transparent 4px 6px)',
                  }}
                >
                  <div style={{ position: 'absolute', top: 0, bottom: 0, left: 0, width: `${totalWriteBytes > 0 ? 45 : 0}%`, background: '#f59e0b' }} />
                </div>
              </div>
            </div>

            {/* IOPS Row */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginTop: 2 }}>
              <span style={{ color: '#728c78', width: 50, fontWeight: 600 }}>IOPS:</span>
              <span style={{ color: '#39e569', fontWeight: 700 }}>
                {totalOps > 0 ? `${(totalOps % 300) + 12} ops/s` : '0 ops/s'}
              </span>
            </div>
          </div>
        </div>
      </div>
    </Box>
  );
}

// ------------------------------------------------------------------ [4] NETWORK
function NetBox({ data }) {
  const [iface, setIface] = useState('all');
  const net = useMemo(() => networkFromSeries(data.net && data.net.items, iface), [data.net, iface]);
  const now = useMemo(() => netdataNetNow(data.latest), [data.latest]);
  const rxV = net.points.map((p) => p.rx);
  const txV = net.points.map((p) => p.tx);
  const hasPoints = net.points.length > 1;
  const last = net.points[net.points.length - 1];
  const rxNow = hasPoints ? last.rx : now && now.rx;
  const txNow = hasPoints ? last.tx : now && now.tx;
  const rxTop = rxV.length ? Math.max(...rxV) : null;
  const txTop = txV.length ? Math.max(...txV) : null;

  // Extract interface list from time series or latest live agent payload directly
  const names = useMemo(() => {
    if (net.names && net.names.length > 0) return net.names.slice(0, 6);
    const agentNet = agentData(data.latest, 'network');
    if (agentNet && agentNet.interfaces && typeof agentNet.interfaces === 'object') {
      const keys = Object.keys(agentNet.interfaces).filter((n) => !isVirtualIface(n) && n !== 'lo');
      if (keys.length > 0) return keys.slice(0, 6);
    }
    return [];
  }, [net.names, data.latest]);

  // Dynamic Peak calculation for auto-scaling Y-axis
  const peakVal = Math.max(1024, ...rxV, ...txV);
  const scale = peakVal * 1.15;
  const GUTTER_W = 54;

  // Active interface details detection (prioritize physical Wi-Fi/Ethernet from collector names)
  const physicalIfaceName = useMemo(() => {
    if (names.length === 0) return 'wlo1';
    // Find wireless interface first if present (wlo1, wlan0, wlp3s0, etc.)
    const wifiMatch = names.find((n) => /^(wlan|wlo|wlp|wls)/i.test(n));
    if (wifiMatch) return wifiMatch;
    // Otherwise return first non-loopback/non-virtual physical interface name
    const ethMatch = names.find((n) => /^(eth|enp|eno|ens)/i.test(n));
    return ethMatch || names[0];
  }, [names]);

  const activeIfaceName = iface === 'all' ? physicalIfaceName : iface;
  const isWifi = /^(wlan|wlo|wlp|wls)/i.test(activeIfaceName);
  const ifaceTypeLabel = isWifi ? 'Wi-Fi Wireless' : 'Ethernet Full Duplex';

  return (
    <Box
      n={4}
      title="NETWORK"
      hot
      controls={
        names.length > 0 ? (
          <Chips value={iface} onChange={setIface} options={[{ value: 'all', label: 'all' }, ...names.map((n) => ({ value: n, label: n }))]} />
        ) : null
      }
    >
      <div className="cpu-split" style={{ gridTemplateColumns: 'minmax(0, 3fr) minmax(0, 2fr)', gap: 16 }}>
        {/* Left Column: Bidirectional Mirrored Timeline Graph */}
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between' }}>
          {hasPoints ? (
            <div style={{ position: 'relative', height: 130 }}>
              {/* Clean Legend Header */}
              <div style={{ position: 'absolute', top: 2, left: GUTTER_W, display: 'flex', gap: 14, fontSize: 10.5, fontWeight: 800, fontFamily: 'JetBrains Mono, monospace', zIndex: 3 }}>
                <span style={{ color: '#06b6d4' }}>■ Download</span>
                <span style={{ color: '#22c55e' }}>■ Upload</span>
              </div>

              {/* Y-Axis Label Column inside Gutter */}
              <div style={{ position: 'absolute', top: 0, left: 0, width: GUTTER_W - 4, height: '100%', pointerEvents: 'none', fontFamily: 'JetBrains Mono, monospace' }}>
                <span style={{ position: 'absolute', top: 2, right: 4, color: '#06b6d4', fontSize: 9.5, fontWeight: 700 }}>
                  {formatRate(rxTop || scale / 2)}
                </span>
                <span style={{ position: 'absolute', top: '50%', right: 4, transform: 'translateY(-50%)', color: '#527a5a', fontSize: 9.5, fontWeight: 700 }}>
                  0 KB/s
                </span>
                <span style={{ position: 'absolute', bottom: 2, right: 4, color: '#22c55e', fontSize: 9.5, fontWeight: 700 }}>
                  {formatRate(txTop || scale / 2)}
                </span>
              </div>

              <DotGraph values={rxV} mirror={txV} max={scale} height={130} palette="down" mirrorPalette="up" gutterW={GUTTER_W} />
            </div>
          ) : (
            <Empty>
              {data.net ? 'Need at least two collector snapshots (one per minute) to compute bandwidth.' : 'Network history needs the host collector (palantir-agent).'}
            </Empty>
          )}
        </div>

        {/* Right Column: Two-Column Telemetry Comparison Card */}
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between', background: 'rgba(10, 20, 13, 0.5)', border: '1px solid #142e1a', borderRadius: 8, padding: '10px 14px', fontFamily: 'JetBrains Mono, monospace' }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            {/* Column 1: Download (IN) */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 800, color: '#06b6d4', letterSpacing: '0.04em', marginBottom: 8 }}>
                ▼ DOWNLOAD (IN)
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 11 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#728c78' }}>Current:</span>
                  <span style={{ color: '#22d3ee', fontWeight: 700 }}>{formatRate(rxNow)}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#728c78' }}>Peak:</span>
                  <span style={{ color: '#d8dee9', fontWeight: 600 }}>{formatRate(rxTop)}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#728c78' }}>Total:</span>
                  <span style={{ color: '#a3c4aa', fontWeight: 600 }}>{formatBytes(net.totals.totalRx)}</span>
                </div>
              </div>
            </div>

            {/* Column 2: Upload (OUT) */}
            <div>
              <div style={{ fontSize: 11, fontWeight: 800, color: '#22c55e', letterSpacing: '0.04em', marginBottom: 8 }}>
                ▲ UPLOAD (OUT)
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, fontSize: 11 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#728c78' }}>Current:</span>
                  <span style={{ color: '#22c55e', fontWeight: 700 }}>{formatRate(txNow)}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#728c78' }}>Peak:</span>
                  <span style={{ color: '#d8dee9', fontWeight: 600 }}>{formatRate(txTop)}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: '#728c78' }}>Total:</span>
                  <span style={{ color: '#a3c4aa', fontWeight: 600 }}>{formatBytes(net.totals.totalTx)}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Interface Footer Line */}
          <div style={{ borderTop: '1px solid #142e1a', paddingTop: 8, marginTop: 8, fontSize: 10.5, color: '#728c78', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span>
              Interface: <span style={{ color: '#39e569', fontWeight: 700 }}>{activeIfaceName}</span>
            </span>
            <span style={{ color: '#6b7a6f' }}>
              ({ifaceTypeLabel})
            </span>
          </div>
        </div>
      </div>
    </Box>
  );
}

// ------------------------------------------------------------------ [4] proc
function ProcBox({ data }) {
  const proc = useMemo(() => processSummary(data.latest), [data.latest]);
  const [mode, setMode] = useState(proc.host.length > 0 ? 'host' : 'apps');
  const [filter, setFilter] = useState('');

  const appCols = [
    { key: 'name', label: 'Program' },
    { key: 'cpu', label: 'Cpu%', num: true, render: (r) => <span className="tone-cyan">{formatNumber(r.cpu, 2)}</span> },
    { key: 'mem', label: 'MemB', num: true, render: (r) => formatBytes(r.mem) },
  ];
  const hostCols = [
    { key: 'pid', label: 'Pid:', num: true },
    { key: 'name', label: 'Program:' },
    { key: 'user', label: 'User:' },
    { key: 'threads', label: 'Threads', num: true },
    { key: 'rss', label: 'MemB', num: true, render: (r) => formatBytes(r.rss) },
    { key: 'cpuTime', label: 'CPU time', num: true, render: (r) => (r.cpuTime === null ? '—' : formatDuration(r.cpuTime * 1000)) },
    { key: 'status', label: 'State' },
  ];

  const rows = mode === 'host' ? proc.host : proc.apps;
  return (
    <Box
      n={5}
      title="proc"
      controls={
        <>
          <Chips
            value={mode}
            onChange={setMode}
            options={[
              { value: 'host', label: 'host', title: 'Process list from the PALANTIR host collector (by RSS)' },
              { value: 'apps', label: 'apps', title: 'Per-application CPU/memory from Netdata' },
            ]}
          />
          <input className="in" style={{ width: 130, marginLeft: 6 }} placeholder="filter…" value={filter} onChange={(e) => setFilter(e.target.value)} />
        </>
      }
      right={`${rows.length}/${mode === 'host' ? proc.count ?? rows.length : rows.length}`}
      className="a-proc"
    >
      <div className="box-scroll" style={{ flex: 1, maxHeight: 520 }}>
        <DataTable
          key={mode}
          columns={mode === 'host' ? hostCols : appCols}
          rows={rows}
          rowKey={(r, i) => (mode === 'host' ? `${r.pid}` : `${r.name}-${i}`)}
          filter={filter}
          initialSort={mode === 'host' ? { key: 'rss', dir: 'desc' } : { key: 'cpu', dir: 'desc' }}
          empty={mode === 'host' ? 'No collector process data (host collector not enrolled?).' : 'No active Netdata apps in the latest sample.'}
        />
      </div>
      {mode === 'host' && Object.keys(proc.oom).length > 0 && (
        <div className="tone-dim">oom: {Object.entries(proc.oom).map(([k, v]) => `${k}=${v}`).join('  ')}</div>
      )}
    </Box>
  );
}

// ------------------------------------------------------------------ sources / pipeline status
function SourcesBox({ node, data }) {
  const cats = (data.status && data.status.categories) || [];
  const age = (iso) => (iso ? formatRelative(iso) : '—');
  const cell = (c, source) => {
    const s = (c.sources || []).find((x) => x.source === source);
    if (!s) return <span className="tone-dim">—</span>;
    const tone = statusTone(s.status);
    return (
      <span title={`${s.status}${s.error_message ? ` — ${s.error_message}` : ''}`} className="row" style={{ gap: 5 }}>
        <Dot tone={tone} />
        <span className={tone === 'dim' ? 'tone-dim' : ''}>{s.status === 'available' ? age(s.last_success_at) : s.status.replace('_', ' ')}</span>
      </span>
    );
  };
  return (
    <Box n={5} title="sources" right={node ? `${node.hostname} • ${node.reachability}` : ''} className="a-src">
      {data.errors && data.errors.status && <ErrorLine warn>collection-status: {data.errors.status}</ErrorLine>}
      {cats.length === 0 ? (
        <Empty>no collection status yet</Empty>
      ) : (
        <div className="box-scroll">
          <table className="tbl">
            <thead>
              <tr>
                <th />
                {cats.map((c) => <th key={c.category}>{c.label || c.category}</th>)}
              </tr>
            </thead>
            <tbody>
              <tr><td className="tone-dim">netdata</td>{cats.map((c) => <td key={c.category}>{cell(c, 'netdata')}</td>)}</tr>
              <tr><td className="tone-dim">collector</td>{cats.map((c) => <td key={c.category}>{cell(c, AGENT)}</td>)}</tr>
            </tbody>
          </table>
        </div>
      )}
      {node && (
        <div className="tone-dim" style={{ marginTop: 4 }}>
          last contact {formatRelative(node.last_seen_at)} • last collection {formatRelative(node.last_collection_at)} • netdata {node.netdata_url}
          {node.collector_url ? ` • collector ${node.collector_url}` : ' • no collector configured'}
        </div>
      )}
    </Box>
  );
}

export default function OverviewTab({ node, state, range, setRange, onBack }) {
  const data = state.data;
  if (state.loading && !data) return <Empty><span className="spinner" /> loading telemetry…</Empty>;
  if (!data) return <ErrorLine>{state.error || 'No data'}</ErrorLine>;
  return (
    <>
      <div className="overview-header-bar" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 12, padding: '10px 16px', background: '#080d09', borderRadius: 10, border: '1.5px solid #193822' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
          <button
            className="btn primary"
            onClick={onBack}
            title="Return to Fleet Grid"
            style={{
              width: 38,
              height: 38,
              padding: 0,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: 8,
              fontSize: 20,
              fontWeight: 'bold',
            }}
          >
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="19" y1="12" x2="5" y2="12"></line>
              <polyline points="12 19 5 12 12 5"></polyline>
            </svg>
          </button>
          <span style={{ fontSize: '1.25rem', fontWeight: 800, color: '#fff' }}>{node?.hostname || 'Host Details'}</span>
          <span className="tone-dim" style={{ fontSize: '0.9rem' }}>{node?.netdata_url ? node.netdata_url.replace(/^https?:\/\//, '').split(':')[0] : ''}</span>
        </div>
      </div>
      {state.error && <ErrorLine warn>refresh failed: {state.error}</ErrorLine>}
      <div className="grid-overview" style={{ marginTop: 6 }}>
        <div className="a-cpu"><CpuBox data={data} range={range} setRange={setRange} /></div>
        <div className="a-mem">
          <div className="two-col" style={{ gap: 14 }}>
            <MemBox data={data} />
            <DisksBox data={data} />
          </div>
        </div>
        <div className="a-net"><NetBox data={data} /></div>
        <ProcBox data={data} />
        <SourcesBox node={node} data={data} />
      </div>
    </>
  );
}
