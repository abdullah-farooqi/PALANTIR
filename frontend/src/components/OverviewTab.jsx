import { useEffect, useMemo, useRef, useState } from 'react';
import { Box, Chips, DataTable, Dot, Empty, ErrorLine, DotGraph, MeterRow, Meter } from './ui';
import {
  AGENT, RANGES, agentData, isVirtualIface, networkNow, networkFromSeries, processSummary, seriesToPoints, storageFromSeries, storageSummary, systemSummary,
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
  const topCpu = useMemo(() => {
    const rawList = proc.host && proc.host.length > 0 ? proc.host : proc.apps || [];
    if (rawList.length === 0) return [];

    const map = new Map();
    rawList.forEach((item) => {
      const prog = item.name || 'unknown';
      if (item.cpu === null || item.cpu === undefined) return; // not measured yet: never counted as 0
      const cpuVal = item.cpu;
      const memVal = item.rss ?? item.mem ?? 0;
      if (!map.has(prog)) {
        map.set(prog, { cpu: 0, mem: 0 });
      }
      const existing = map.get(prog);
      existing.cpu += cpuVal;
      existing.mem += memVal;
    });

    const combined = [];
    map.forEach((val, name) => {
      combined.push({ name, cpu: Math.min(100.0, val.cpu), mem: val.mem });
    });

    // Rank strictly by instantaneous CPU % first, then by Memory footprint
    combined.sort((a, b) => b.cpu - a.cpu || b.mem - a.mem);
    return combined.slice(0, 6);
  }, [proc.host, proc.apps]);

  const maxAppCpu = useMemo(() => Math.max(1, ...topCpu.map((a) => a.cpu || 0)), [topCpu]);

  const coreCount = sys.cores || (sys.cpuCoresPct && sys.cpuCoresPct.length) || 0;
  const coresList = useMemo(() => {
    if (sys.cpuCoresPct && sys.cpuCoresPct.length > 0) {
      return sys.cpuCoresPct.map((pct, idx) => ({ id: idx + 1, pct: Math.min(100, Math.max(0, pct)) }));
    }
    return [];
  }, [sys.cpuCoresPct]);

  const coresLabel = coreCount > 0 ? ` (${coreCount} Cores)` : '';
  const cpuHeaderTitle = sys.cpuModel ? `CPU • ${sys.cpuModel}${coresLabel}` : `CPU${coresLabel}`;

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
            <Empty>No data available</Empty>
          ) : (
            <StackedCpuGraph points={points} height={215} />
          )}
        </div>

        {/* Middle Column (~25%): Core Matrix Grid */}
        <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between', background: 'rgba(10, 20, 13, 0.5)', border: '1px solid #142e1a', borderRadius: 8, padding: '10px 12px' }}>
          <div>
            <div style={{ fontSize: 11, fontWeight: 800, color: '#39e569', letterSpacing: '0.05em', marginBottom: 8 }}>
              CORES{coreCount > 0 ? ` (${coreCount})` : ''}
            </div>
            {coresList.length === 0 && <Empty>No data available</Empty>}
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
            <div style={{ color: '#728c78', display: 'flex', alignItems: 'center', gap: 6, width: '100%', marginBottom: 5 }}>
              <span style={{ color: '#728c78', fontWeight: 600 }}>Load:</span>
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, flex: 1, justifyContent: 'flex-end' }}>
                <span style={{ color: '#39e569', fontWeight: 700 }}>
                  {l1} <span style={{ color: '#4a6350', fontWeight: 400, fontSize: 9.5 }}>(1m)</span>
                </span>
                <span style={{ color: '#39e569', fontWeight: 700 }}>
                  {l5} <span style={{ color: '#4a6350', fontWeight: 400, fontSize: 9.5 }}>(5m)</span>
                </span>
                <span style={{ color: '#39e569', fontWeight: 700 }}>
                  {l15} <span style={{ color: '#4a6350', fontWeight: 400, fontSize: 9.5 }}>(15m)</span>
                </span>
              </div>
            </div>
            <div style={{ color: '#728c78', display: 'flex', justifyContent: 'space-between', width: '100%', flexWrap: 'nowrap', whiteSpace: 'nowrap' }}>
              <span>Current: <span style={{ color: '#39e569', fontWeight: 700 }}>{sys.cpuPct != null ? formatPercent(sys.cpuPct, 0) : '—'}</span></span>
              <span>Avg: <span style={{ color: '#22d3ee', fontWeight: 600 }}>{formatPercent(avg, 0)}</span></span>
              <span>Max: <span style={{ color: '#fbbf24', fontWeight: 600 }}>{formatPercent(peak, 0)}</span></span>
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
              <Empty>No data available</Empty>
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
                      <span style={{ color: '#4dd0e1', fontFamily: 'JetBrains Mono, monospace', fontWeight: 700, fontSize: 11, width: 46, textAlign: 'right', flexShrink: 0 }}>
                        {a.cpu > 0 && a.cpu < 0.1 ? a.cpu.toFixed(2) : formatNumber(a.cpu, 1)}%
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

function MultiSegmentRamBar({ usedPct = 0, height = 10 }) {
  const uPct = Math.max(0, Math.min(100, usedPct));
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
    </div>
  );
}

function MemBox({ data }) {
  const sys = useMemo(() => systemSummary(data.latest), [data.latest]);
  const proc = useMemo(() => processSummary(data.latest), [data.latest]);
  const { mem, swap } = sys;

  const hasMem = mem.total !== null && mem.total > 0 && mem.used !== null;
  const total = hasMem ? mem.total : 1;
  // `used` is "total - available": it already EXCLUDES reclaimable cache, so the cache is drawn on top of it.
  const usedPct = hasMem ? Math.min(100, (mem.used / total) * 100) : 0;
  const buffCache = (mem.buffers || 0) + (mem.cached || 0);
  const buffCachePct = hasMem ? Math.min(100 - usedPct, (buffCache / total) * 100) : 0;
  const memTotalPct = hasMem ? Math.min(100, Math.round(mem.pct ?? usedPct)) : null;

  const topRamApps = useMemo(() => {
    const rawList = proc.host && proc.host.length > 0 ? proc.host : proc.apps || [];
    if (rawList.length === 0) return [];

    const map = new Map();
    rawList.forEach((item) => {
      const prog = item.name || 'unknown';
      const memVal = item.rss ?? item.mem ?? 0;
      if (!map.has(prog)) {
        map.set(prog, 0);
      }
      map.set(prog, map.get(prog) + memVal);
    });

    const combined = [];
    map.forEach((totalRss, name) => {
      if (totalRss > 0) combined.push({ name, rss: totalRss });
    });

    return combined.sort((a, b) => b.rss - a.rss).slice(0, 4);
  }, [proc.host, proc.apps]);

  const maxAppRss = useMemo(() => Math.max(1, ...topRamApps.map((a) => a.rss || 0)), [topRamApps]);

  return (
    <Box n={2} title="MEMORY" hot style={{ height: '100%' }}>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between', gap: 12 }}>
        {/* Upper Section: RAM & Swap */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, height: 110, justifyContent: 'center' }}>
          {!hasMem ? <Empty>No data available</Empty> : (
          <>
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
              <MultiSegmentRamBar usedPct={memTotalPct ?? usedPct} height={10} />
              <span style={{ color: '#39e569', fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, fontSize: 11, minWidth: 32, textAlign: 'right' }}>
                {memTotalPct}%
              </span>
            </div>
          </div>

          {/* Swap Header & Bar */}
          {swap.total === null ? (
            <div style={{ fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', color: '#728c78' }}>Swap: no data available</div>
          ) : swap.total === 0 ? (
            <div style={{ fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', color: '#728c78' }}>Swap: not configured</div>
          ) : (
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', marginBottom: 4 }}>
              <span style={{ color: '#728c78' }}>
                Swap: <span style={{ color: '#d8dee9' }}>{formatBytes(swap.used)} / {formatBytes(swap.total)}</span>
              </span>
              <span style={{ color: swap.pct > 70 ? '#f0616d' : '#728c78' }}>
                {swap.pct !== null ? `${Math.round(swap.pct)}%` : '—'}
              </span>
            </div>
            <SegmentedBar pct={swap.pct || 0} tone={swap.pct > 70 ? 'usage' : 'cool'} height={8} />
          </div>
          )}
          </>
          )}
        </div>

        {/* Lower Section: TOP APPS BY RAM */}
        <div style={{ borderTop: '1px solid #142e1a', paddingTop: 10 }}>
          <div style={{ fontSize: 11, fontWeight: 800, color: '#39e569', letterSpacing: '0.05em', marginBottom: 8 }}>
            TOP APPS BY RAM
          </div>
          {topRamApps.length === 0 ? (
            <Empty>No data available</Empty>
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

  // Compute real-time rates and IOPS from snapshot deltas across storageSeries
  const ioRates = useMemo(() => {
    if (st.ioNow) return st.ioNow;
    const items = data.storageSeries && data.storageSeries.items ? data.storageSeries.items : [];
    return storageFromSeries(items);
  }, [data.storageSeries, st.ioNow]);

  const readRate = ioRates.readRate;
  const writeRate = ioRates.writeRate;
  const iops = ioRates.iops;
  const busyPct = ioRates.busyPct;

  // Track real peak read and write rates observed
  const [peakRead, setPeakRead] = useState(null);
  const [peakWrite, setPeakWrite] = useState(null);

  useEffect(() => {
    if (typeof readRate === 'number' && readRate > 0) {
      setPeakRead((prev) => (prev === null ? readRate : Math.max(prev, readRate)));
    }
  }, [readRate]);

  useEffect(() => {
    if (typeof writeRate === 'number' && writeRate > 0) {
      setPeakWrite((prev) => (prev === null ? writeRate : Math.max(prev, writeRate)));
    }
  }, [writeRate]);

  const fsList = st.filesystems || [];

  return (
    <Box n={3} title="DISKS" hot style={{ height: '100%' }}>
      <div style={{ display: 'flex', flexDirection: 'column', height: '100%', justifyContent: 'space-between', gap: 12 }}>
        {/* Upper Section: Mount Point Storage Usage */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8, height: 110, justifyContent: 'center', overflowY: 'auto', paddingRight: 2 }}>
          {fsList.length === 0 ? (
            <Empty>No data available</Empty>
          ) : (
            fsList.slice(0, 3).map((f) => {
              const tot = f.total ?? f.totalBytes ?? null;
              const usd = f.used ?? f.usedBytes ?? null;
              const fre = f.free ?? f.freeBytes ?? null;
              let p = f.pct;
              if ((p === null || p === undefined) && tot && usd !== null) p = Math.min(100, (usd / tot) * 100);
              const pctVal = p !== null && p !== undefined ? Math.round(p) : null;

              // Color logic: bright green (<70%), amber/yellow (70-90%), red (>=90%)
              let barColor = '#22c55e'; // Bright green (<70%)
              let textColor = '#39e569';
              if (pctVal !== null && pctVal >= 90) {
                barColor = '#f0616d'; // Bright red (>=90%)
                textColor = '#f0616d';
              } else if (pctVal !== null && pctVal >= 70) {
                barColor = '#f59e0b'; // Amber / Yellow (70-90%)
                textColor = '#fbbf24';
              }

              return (
                <div key={f.mount + f.device}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, fontWeight: 700, fontFamily: 'JetBrains Mono, monospace', marginBottom: 2 }}>
                    <span style={{ color: '#d8dee9' }}>
                      {f.mount} {f.fs && <span style={{ color: '#6b7a6f', fontWeight: 500 }}>({f.fs})</span>}
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
                      <div style={{ position: 'absolute', top: 0, bottom: 0, left: 0, width: `${pctVal ?? 0}%`, background: barColor }} />
                    </div>
                    <span style={{ color: textColor, fontFamily: 'JetBrains Mono, monospace', fontWeight: 800, fontSize: 11, minWidth: 32, textAlign: 'right' }}>
                      {pctVal !== null ? `${pctVal}%` : '—'}
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
          {diskIo.length === 0 ? (
            <Empty>No data available</Empty>
          ) : (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12, textAlign: 'left', fontFamily: 'JetBrains Mono, monospace' }}>
              {/* Column 1: READ */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: '#6b7a6f', letterSpacing: '0.06em' }}>READ</span>
                <span style={{ fontSize: 13, fontWeight: 800, color: '#22d3ee' }}>
                  {typeof readRate === 'number' ? formatRate(readRate) : '—'}
                </span>
                <span style={{ fontSize: 10, color: '#4a6350', fontWeight: 500 }}>
                  {peakRead !== null ? `peak: ${formatRate(peakRead)}` : 'peak: —'}
                </span>
              </div>

              {/* Column 2: WRITE */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: '#6b7a6f', letterSpacing: '0.06em' }}>WRITE</span>
                <span style={{ fontSize: 13, fontWeight: 800, color: '#fbbf24' }}>
                  {typeof writeRate === 'number' ? formatRate(writeRate) : '—'}
                </span>
                <span style={{ fontSize: 10, color: '#4a6350', fontWeight: 500 }}>
                  {peakWrite !== null ? `peak: ${formatRate(peakWrite)}` : 'peak: —'}
                </span>
              </div>

              {/* Column 3: IOPS */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                <span style={{ fontSize: 10, fontWeight: 700, color: '#6b7a6f', letterSpacing: '0.06em' }}>IOPS</span>
                <span style={{ fontSize: 13, fontWeight: 800, color: '#39e569' }}>
                  {typeof iops === 'number' ? `${formatCount(Math.round(iops))} ops/s` : '—'}
                </span>
                <span style={{ fontSize: 10, color: '#4a6350', fontWeight: 500 }}>
                  {typeof busyPct === 'number' ? `busy: ${busyPct}%` : 'busy: —'}
                </span>
              </div>
            </div>
          )}
        </div>
      </div>
    </Box>
  );
}

// ------------------------------------------------------------------ [4] NETWORK
function NetBox({ data }) {
  const [iface, setIface] = useState('all');
  const net = useMemo(() => networkFromSeries(data.net && data.net.items, iface), [data.net, iface]);
  const now = useMemo(() => networkNow(data.latest), [data.latest]);
  const rxV = net.points.map((p) => p.rx);
  const txV = net.points.map((p) => p.tx);
  const hasPoints = net.points.length > 1;
  const last = net.points[net.points.length - 1];
  const rxNow = now && now.rx !== null && iface === 'all' ? now.rx : hasPoints ? last.rx : null;
  const txNow = now && now.tx !== null && iface === 'all' ? now.tx : hasPoints ? last.tx : null;
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

  // Dynamic Peak calculation for auto-scaling Y-axis (scale strictly to non-zero network traffic)
  const maxRxTx = Math.max(0, ...rxV, ...txV);
  const peakVal = maxRxTx > 0 ? maxRxTx : 1;
  const scale = peakVal * 1.15;
  const GUTTER_W = 54;

  // Active interface details detection (prioritize physical Wi-Fi/Ethernet from collector names)
  const physicalIfaceName = useMemo(() => {
    if (names.length === 0) return null;
    // Find wireless interface first if present (wlo1, wlan0, wlp3s0, etc.)
    const wifiMatch = names.find((n) => /^(wlan|wlo|wlp|wls)/i.test(n));
    if (wifiMatch) return wifiMatch;
    // Otherwise return first non-loopback/non-virtual physical interface name
    const ethMatch = names.find((n) => /^(eth|enp|eno|ens)/i.test(n));
    return ethMatch || names[0];
  }, [names]);

  const activeIfaceName = iface === 'all' ? physicalIfaceName : iface;
  const isWifi = !!activeIfaceName && /^(wlan|wlo|wlp|wls)/i.test(activeIfaceName);
  const ifaceTypeLabel = !activeIfaceName ? null : isWifi ? 'Wi-Fi Wireless' : 'Wired';

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
                  {formatRate(rxTop)}
                </span>
                <span style={{ position: 'absolute', top: '50%', right: 4, transform: 'translateY(-50%)', color: '#527a5a', fontSize: 9.5, fontWeight: 700 }}>
                  0 KB/s
                </span>
                <span style={{ position: 'absolute', bottom: 2, right: 4, color: '#22c55e', fontSize: 9.5, fontWeight: 700 }}>
                  {formatRate(txTop)}
                </span>
              </div>

              <DotGraph values={rxV} mirror={txV} max={scale} height={130} palette="down" mirrorPalette="up" gutterW={GUTTER_W} />
            </div>
          ) : (
            <Empty>
              No data available
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
                  <span style={{ color: '#a3c4aa', fontWeight: 600 }}>{formatBytes(net.totals.totalRx ?? (now && now.totalRx))}</span>
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
                  <span style={{ color: '#a3c4aa', fontWeight: 600 }}>{formatBytes(net.totals.totalTx ?? (now && now.totalTx))}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Interface Footer Line */}
          <div style={{ borderTop: '1px solid #142e1a', paddingTop: 8, marginTop: 8, fontSize: 10.5, color: '#728c78', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
            <span>
              Interface: <span style={{ color: '#39e569', fontWeight: 700 }}>{activeIfaceName || '—'}</span>
            </span>
            <span style={{ color: '#6b7a6f' }}>
              {ifaceTypeLabel ? `(${ifaceTypeLabel})` : ''}
            </span>
          </div>
        </div>
      </div>
    </Box>
  );
}

// Helper for mapping numeric UIDs to clean usernames
const mapUsername = (user) => {
  if (user === null || user === undefined || user === '') return '—';
  const u = String(user).trim();
  if (u === '0' || u === 'root') return 'root';
  if (u === '1000' || u === 'user') return 'user';
  if (u === '70' || u === 'postgres') return 'postgres';
  if (u === '957' || u === 'libvirt-qemu') return 'libvirt-qemu';
  if (u === '101' || u === 'systemd-resolve') return 'systemd-resolve';
  if (/^\d+$/.test(u)) return `uid:${u}`;
  return u;
};

// Micro badge / dot indicator for process state
const renderStateBadge = (stateStr) => {
  if (!stateStr) return <span className="tone-dim">—</span>;
  const s = String(stateStr).trim().toUpperCase();
  const first = s.charAt(0);

  if (first === 'R') {
    return (
      <span className="badge" style={{ background: 'rgba(6, 182, 212, 0.15)', borderColor: '#06b6d4', color: '#22d3ee', fontWeight: 700, padding: '1px 5px', borderRadius: 4 }}>
        R
      </span>
    );
  }
  if (first === 'S') {
    return (
      <span className="badge" style={{ background: 'rgba(34, 197, 94, 0.12)', borderColor: '#15803d', color: '#4ade80', fontWeight: 600, padding: '1px 5px', borderRadius: 4 }}>
        S
      </span>
    );
  }
  if (first === 'Z') {
    return (
      <span className="badge" style={{ background: 'rgba(239, 68, 68, 0.2)', borderColor: '#ef4444', color: '#f87171', fontWeight: 800, padding: '1px 5px', borderRadius: 4 }}>
        Z
      </span>
    );
  }
  if (first === 'D' || first === 'T' || first === 'I') {
    return (
      <span className="badge" style={{ background: 'rgba(229, 192, 123, 0.15)', borderColor: '#e5c07b', color: '#facc15', fontWeight: 600, padding: '1px 5px', borderRadius: 4 }}>
        {first}
      </span>
    );
  }
  return <span className="badge tone-dim">{first}</span>;
};

// ------------------------------------------------------------------ [5] proc
function ProcBox({ data }) {
  const proc = useMemo(() => processSummary(data.latest), [data.latest]);
  const [mode, setMode] = useState(proc.host.length > 0 ? 'host' : 'apps');
  const [filter, setFilter] = useState('');
  const [expandedGroups, setExpandedGroups] = useState(new Set());

  const toggleGroup = (groupName) => {
    setExpandedGroups((prev) => {
      const next = new Set(prev);
      if (next.has(groupName)) next.delete(groupName);
      else next.add(groupName);
      return next;
    });
  };

  // Group processes by program name for [apps] tab
  const { groupedApps, sortedGroupList } = useMemo(() => {
    const rawList = proc.host.length > 0 ? proc.host : proc.apps;
    const map = new Map();

    rawList.forEach((item) => {
      const prog = item.name || 'unknown';
      if (!map.has(prog)) {
        map.set(prog, {
          name: prog,
          procs: [],
          totalMem: 0,
          totalCpu: null,
          totalThreads: 0,
          users: new Set(),
        });
      }
      const g = map.get(prog);
      g.procs.push(item);
      const memVal = item.rss ?? item.mem ?? 0;
      g.totalMem += memVal;
      if (item.cpu !== null && item.cpu !== undefined) g.totalCpu = (g.totalCpu ?? 0) + item.cpu;
      g.totalThreads += item.threads ?? 1;
      if (item.user) g.users.add(item.user);
    });

    const groupList = [];
    map.forEach((g) => {
      groupList.push({
        isGroup: true,
        key: `group-${g.name}`,
        name: g.name,
        count: g.procs.length,
        mem: g.totalMem,
        cpu: g.totalCpu,
        threads: g.totalThreads,
        user: [...g.users].map(mapUsername).join(', ') || 'user',
        children: g.procs,
      });
    });

    // Sort parent groups by Memory descending by default
    groupList.sort((a, b) => b.mem - a.mem);

    // Build flat row list preserving exact tree hierarchy
    const result = [];
    groupList.forEach((group) => {
      const isExpanded = expandedGroups.has(group.name);
      result.push({
        ...group,
        isExpanded,
      });

      if (isExpanded) {
        // Sort children by RAM descending within group
        const sortedChildren = [...group.children].sort((a, b) => (b.rss ?? b.mem ?? 0) - (a.rss ?? a.mem ?? 0));
        sortedChildren.forEach((child, idx) => {
          result.push({
            isChild: true,
            parentName: group.name,
            key: `child-${group.name}-${child.pid || idx}`,
            pid: child.pid || '—',
            name: child.name,
            user: child.user,
            threads: child.threads ?? 1,
            mem: child.rss ?? child.mem ?? 0,
            cpuTime: child.cpuTime,
            status: child.status,
            cpu: child.cpu,
          });
        });
      }
    });

    return { groupedApps: result, sortedGroupList: groupList };
  }, [proc.host, proc.apps, expandedGroups]);

  const totalProcCount = mode === 'host' ? (proc.count ?? proc.host.length) : proc.host.length || proc.apps.length;
  const oomKillsCount = mode === 'host' ? Object.values(proc.oom || {}).reduce((a, b) => a + (Number(b) || 0), 0) : 0;

  const appCols = [
    {
      key: 'name',
      label: 'Program',
      sortable: false,
      value: (r) => r.name,
      render: (r) => {
        if (r.isChild) {
          return (
            <span style={{ paddingLeft: 20, color: '#94a3b8', fontSize: 11.5, fontFamily: 'JetBrains Mono, monospace' }}>
              └ PID {r.pid}
            </span>
          );
        }
        return (
          <div
            onClick={(e) => {
              e.stopPropagation();
              toggleGroup(r.name);
            }}
            style={{ cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6, fontWeight: 700, color: '#e2e8f0', userSelect: 'none' }}
          >
            <span style={{ color: '#39e569', fontSize: 11, width: 12, display: 'inline-block' }}>{r.isExpanded ? '▼' : '▶'}</span>
            <span>{r.name}</span>
            <span style={{ fontSize: 10.5, fontWeight: 600, color: '#728c78', background: 'rgba(20, 46, 26, 0.6)', padding: '1px 6px', borderRadius: 4 }}>
              ({r.count} procs)
            </span>
          </div>
        );
      },
    },
    {
      key: 'threads',
      label: 'Threads',
      num: true,
      sortable: false,
      value: (r) => r.threads,
      render: (r) => <span style={{ color: r.isChild ? '#64748b' : '#cbd5e1', fontWeight: 600 }}>{r.threads ?? '—'}</span>,
    },
    {
      key: 'mem',
      label: 'MEM',
      num: true,
      sortable: false,
      value: (r) => r.mem,
      render: (r) => <span style={{ color: r.isChild ? '#0284c7' : '#06b6d4', fontWeight: 700 }}>{formatBytes(r.mem)}</span>,
    },
  ];

  const hostCols = [
    {
      key: 'pid',
      label: 'PID',
      num: false,
      value: (r) => r.pid,
      render: (r) => <span style={{ color: '#6b7a6f', fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5 }}>{r.pid}</span>,
    },
    {
      key: 'name',
      label: 'Program',
      value: (r) => r.name,
      render: (r) => (
        <span
          style={{
            fontWeight: 600,
            color: '#e2e8f0',
            display: 'inline-block',
            maxWidth: 180,
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            verticalAlign: 'bottom',
          }}
          title={r.name}
        >
          {r.name}
        </span>
      ),
    },
    {
      key: 'user',
      label: 'User',
      value: (r) => mapUsername(r.user),
      render: (r) => <span style={{ color: '#94a3b8', fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5 }}>{mapUsername(r.user)}</span>,
    },
    {
      key: 'threads',
      label: 'Threads',
      num: true,
      value: (r) => r.threads,
      render: (r) => <span style={{ color: '#cbd5e1', fontWeight: 600 }}>{r.threads ?? '—'}</span>,
    },
    {
      key: 'rss',
      label: 'MEM',
      num: true,
      value: (r) => r.rss,
      render: (r) => <span style={{ color: '#06b6d4', fontWeight: 700 }}>{formatBytes(r.rss)}</span>,
    },
    {
      key: 'cpu',
      label: 'CPU %',
      num: true,
      value: (r) => r.cpu,
      render: (r) => (
        <span style={{ color: '#22d3ee', fontWeight: 700 }}>
          {r.cpu === null || r.cpu === undefined ? '—' : `${r.cpu > 0 && r.cpu < 0.1 ? r.cpu.toFixed(2) : formatNumber(r.cpu, 1)}%`}
        </span>
      ),
    },
    {
      key: 'status',
      label: 'State',
      num: true,
      value: (r) => r.status,
      render: (r) => renderStateBadge(r.status),
    },
  ];

  const displayRows = mode === 'host' ? proc.host : groupedApps;

  return (
    <Box
      n={5}
      title="PROCESS TABLE"
      controls={
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <Chips
            value={mode}
            onChange={setMode}
            options={[
              { value: 'host', label: 'host', title: 'Process list from the PALANTIR host collector (by RSS)' },
              { value: 'apps', label: 'apps', title: 'Per-application aggregated process grouping' },
            ]}
          />
          <input
            className="in"
            style={{
              width: 140,
              background: '#040805',
              border: '1px solid #1a3821',
              borderRadius: 6,
              padding: '2px 8px',
              fontSize: 11.5,
              color: '#d8dee9',
              outline: 'none',
              fontFamily: 'JetBrains Mono, monospace',
            }}
            placeholder="filter..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>
      }
      right={
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span
            style={{
              background: 'rgba(18, 38, 22, 0.8)',
              border: '1px solid #1c4524',
              borderRadius: 4,
              padding: '1px 7px',
              fontSize: 11,
              fontWeight: 700,
              color: '#39e569',
              letterSpacing: '0.03em',
            }}
          >
            Tasks: {displayRows.length}/{totalProcCount}
          </span>
          {mode === 'host' && (
            <span
              style={{
                background: oomKillsCount > 0 ? 'rgba(239, 68, 68, 0.15)' : 'rgba(15, 28, 18, 0.6)',
                border: oomKillsCount > 0 ? '1px solid #ef4444' : '1px solid #193822',
                borderRadius: 4,
                padding: '1px 7px',
                fontSize: 11,
                fontWeight: 700,
                color: oomKillsCount > 0 ? '#f87171' : '#728c78',
              }}
            >
              OOM Kills: {oomKillsCount}
            </span>
          )}
        </div>
      }
      className="a-proc"
    >
      <div
        className="box-scroll"
        style={{
          flex: 1,
          maxHeight: 460,
          border: '1px solid #142e1a',
          borderRadius: 8,
          background: 'rgba(6, 12, 8, 0.6)',
          overflowY: 'auto',
          marginTop: 4,
          paddingBottom: 10,
        }}
      >
        <DataTable
          key={mode}
          columns={mode === 'host' ? hostCols : appCols}
          rows={displayRows}
          rowKey={(r, i) => (r.key ? r.key : mode === 'host' ? `${r.pid}` : `${r.name}-${i}`)}
          filter={filter}
          initialSort={mode === 'host' ? { key: 'cpu', dir: 'desc' } : null}
          onRowClick={(r) => {
            if (mode === 'apps' && r.isGroup) {
              toggleGroup(r.name);
            }
          }}
          empty="No data available"
        />
      </div>
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
              <tr><td className="tone-dim">collector</td>{cats.map((c) => <td key={c.category}>{cell(c, AGENT)}</td>)}</tr>
            </tbody>
          </table>
        </div>
      )}
      {node && (
        <div className="tone-dim" style={{ marginTop: 4 }}>
          last contact {formatRelative(node.last_seen_at)} • last collection {formatRelative(node.last_collection_at)}
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
          <span className="tone-dim" style={{ fontSize: '0.9rem' }}>{(node?.collector_url || node?.netdata_url) ? (node.collector_url || node.netdata_url).replace(/^https?:\/\//, '').split(':')[0] : ''}</span>
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
      </div>
    </>
  );
}
