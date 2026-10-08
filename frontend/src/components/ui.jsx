import { useEffect, useMemo, useRef, useState } from 'react';

// ------------------------------------------------------------------ Box
// A btop-style panel: thin border with the title sitting in the top edge.
//   <Box n={1} title="cpu" right={<span>…</span>}> … </Box>
export function Box({ n, title, controls, right, hot, className = '', style, children }) {
  return (
    <section className={`box ${hot ? 'hot' : ''} ${className}`} style={style}>
      <div className="box-title">
        <span className="t-edge">┐</span>
        <span className="t-chip">
          {n !== undefined && n !== null && <sup>{n}</sup>}
          <span className="t-name">{title}</span>
        </span>
        <span className="t-edge">┌</span>
        {controls && <span className="t-controls">{controls}</span>}
        <span className="t-line" />
        {right && <span className="t-right">{right}</span>}
      </div>
      {children}
    </section>
  );
}

// ------------------------------------------------------------------ small pieces
export function Dot({ tone = 'dim', pulse = false }) {
  return <span className={`dot ${tone} ${pulse ? 'pulse' : ''}`} />;
}

export function Badge({ tone = 'dim', children, title }) {
  return (
    <span className={`badge tone-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function Spinner() {
  return <span className="spinner" aria-label="loading" />;
}

export function Empty({ children }) {
  return <div className="empty">{children}</div>;
}

export function ErrorLine({ children, warn }) {
  if (!children) return null;
  return <div className={`banner ${warn ? 'warn' : ''}`}>{children}</div>;
}

/** Row of tiny toggle buttons: [a] [b] [c]. */
export function Chips({ options, value, onChange }) {
  return (
    <span className="row" style={{ gap: 2 }}>
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          className={`chip-btn ${value === o.value ? 'on' : ''}`}
          onClick={() => onChange(o.value)}
          title={o.title}
        >
          {o.hotkey && <span className="k">{o.hotkey}</span>}
          {o.label}
        </button>
      ))}
    </span>
  );
}

// ------------------------------------------------------------------ Meter
// Segmented bar like btop's `■■■■▪▪▪`. tone: usage (green->red), free (red->green), cool, warm.
export function Meter({ pct, tone = 'usage' }) {
  const p = Number.isFinite(pct) ? Math.max(0, Math.min(100, pct)) : 0;
  return (
    <div className={`meter ${tone}`} role="progressbar" aria-valuenow={p} aria-valuemin={0} aria-valuemax={100}>
      <i style={{ left: `${p}%` }} />
    </div>
  );
}

/** label · meter · value, one line. */
export function MeterRow({ label, pct, value, tone, sub }) {
  return (
    <div style={{ marginBottom: 3 }}>
      <div className="row" style={{ justifyContent: 'space-between' }}>
        <span className="tone-dim">{label}</span>
        <span>{value}</span>
      </div>
      <div className="row">
        <Meter pct={pct} tone={tone} />
        <span className="tone-dim" style={{ minWidth: '3.6em', textAlign: 'right' }}>
          {Number.isFinite(pct) ? `${Math.round(pct)}%` : '—'}
        </span>
      </div>
      {sub && <div className="tone-dim">{sub}</div>}
    </div>
  );
}

// ------------------------------------------------------------------ DotGraph
// Canvas "braille-ish" dot graph. Values are right-aligned (newest on the right).
// `mirror` draws a second series growing downward from a centre line (network up/down).
const PALETTES = {
  usage: ['#3fb950', '#a9e34b', '#e5c07b', '#f0616d'],
  down: ['#06b6d4', '#22d3ee', '#38bdf8'],
  up: ['#16a34a', '#22c55e', '#4ade80'],
};
function hex(c) {
  return [parseInt(c.slice(1, 3), 16), parseInt(c.slice(3, 5), 16), parseInt(c.slice(5, 7), 16)];
}
function ramp(stops, f) {
  const x = Math.max(0, Math.min(1, f)) * (stops.length - 1);
  const i = Math.min(stops.length - 2, Math.floor(x));
  const a = hex(stops[i]);
  const b = hex(stops[i + 1]);
  const t = x - i;
  return `rgb(${Math.round(a[0] + (b[0] - a[0]) * t)},${Math.round(a[1] + (b[1] - a[1]) * t)},${Math.round(a[2] + (b[2] - a[2]) * t)})`;
}

const CELL = 4;
export function DotGraph({ values = [], mirror = null, max, height = 110, palette = 'usage', mirrorPalette = 'up', topLabel, bottomLabel, gutterW = 0 }) {
  const wrap = useRef(null);
  const canvas = useRef(null);
  const [width, setWidth] = useState(300);

  useEffect(() => {
    if (!wrap.current) return undefined;
    const ro = new ResizeObserver((entries) => {
      const w = Math.floor(entries[0].contentRect.width);
      if (w > 0) setWidth(w);
    });
    ro.observe(wrap.current);
    return () => ro.disconnect();
  }, []);

  const peak = useMemo(() => {
    if (max) return max;
    const all = values.concat(mirror || []).filter((v) => Number.isFinite(v));
    const m = Math.max(0, ...all);
    return m > 0 ? m * 1.15 : 1;
  }, [values, mirror, max]);

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

    const chartW = Math.max(10, width - gutterW);
    const n = Math.max(values.length, mirror ? mirror.length : 0);
    const cw = n > 0 ? Math.max(CELL, Math.min(10, Math.floor(chartW / n))) : CELL;
    const cols = Math.floor(chartW / cw);
    const totalRows = Math.floor(height / CELL);
    const rows = mirror ? Math.floor(totalRows / 2) : totalRows;
    const dot = CELL - 1;
    const dotW = cw - 1;

    // Faint center baseline for mirrored bidirectional mode
    if (mirror) {
      const centerY = rows * CELL;
      ctx.strokeStyle = 'rgba(25, 56, 34, 0.5)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.setLineDash([3, 3]);
      ctx.moveTo(gutterW, centerY);
      ctx.lineTo(width, centerY);
      ctx.stroke();
      ctx.setLineDash([]);
    }

    const draw = (series, pal, dir) => {
      const stops = PALETTES[pal] || PALETTES.usage;
      for (let c = 0; c < cols; c += 1) {
        const idx = series.length - cols + c;
        const v = idx >= 0 ? series[idx] : null;
        const filled = v !== null && Number.isFinite(v) ? Math.min(rows, Math.max(v > 0 ? 1 : 0, Math.round((v / peak) * rows))) : 0;
        for (let r = 0; r < rows; r += 1) {
          const y = dir === 'up' ? (mirror ? rows * CELL : totalRows * CELL) - (r + 1) * CELL : rows * CELL + r * CELL;
          ctx.fillStyle = r < filled ? ramp(stops, rows > 1 ? r / (rows - 1) : 0) : '#0a120c';
          ctx.fillRect(gutterW + c * cw, y, dotW, dot);
        }
      }
    };

    draw(values, palette, 'up');
    if (mirror) draw(mirror, mirrorPalette, 'down');
  }, [values, mirror, peak, width, height, palette, mirrorPalette, gutterW]);

  return (
    <div className="graph-wrap" ref={wrap} style={{ height }}>
      <canvas ref={canvas} />
      {topLabel && <span className="graph-label" style={{ top: 0 }}>{topLabel}</span>}
      {bottomLabel && <span className="graph-label" style={{ bottom: 0 }}>{bottomLabel}</span>}
    </div>
  );
}

// ------------------------------------------------------------------ DataTable
function cmp(a, b) {
  if (a === b) return 0;
  if (a === null || a === undefined) return 1;
  if (b === null || b === undefined) return -1;
  if (typeof a === 'number' && typeof b === 'number') return a - b;
  return String(a).localeCompare(String(b), undefined, { numeric: true });
}

/**
 * columns: [{ key, label, num?, value?(row) -> sortable, render?(row) -> node, search?: bool }]
 * Click a header to sort; `filter` does a case-insensitive substring match across searchable columns.
 */
export function DataTable({ columns, rows, rowKey, filter = '', initialSort, limit = 400, onRowClick, selectedKey, empty = 'nothing to show' }) {
  const [sort, setSort] = useState(initialSort || null);

  const view = useMemo(() => {
    const needle = filter.trim().toLowerCase();
    let list = rows;
    if (needle) {
      list = rows.filter((row) =>
        columns.some((c) => {
          if (c.search === false) return false;
          const v = c.value ? c.value(row) : row[c.key];
          return v !== null && v !== undefined && String(v).toLowerCase().includes(needle);
        })
      );
    }
    if (sort) {
      const col = columns.find((c) => c.key === sort.key);
      if (col) {
        const get = (r) => (col.value ? col.value(r) : r[col.key]);
        list = [...list].sort((a, b) => cmp(get(a), get(b)) * (sort.dir === 'asc' ? 1 : -1));
      }
    }
    return list;
  }, [rows, columns, filter, sort]);

  const toggle = (col) => {
    if (col.sortable === false) return;
    setSort((s) => (s && s.key === col.key ? { key: col.key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key: col.key, dir: col.num ? 'desc' : 'asc' }));
  };

  if (rows.length === 0) return <Empty>{empty}</Empty>;
  return (
    <>
      <table className="tbl">
        <thead>
          <tr>
            {columns.map((c) => (
              <th key={c.key} className={`${c.num ? 'num' : ''} ${c.sortable === false ? '' : 'sortable'}`} onClick={() => toggle(c)}>
                {c.label}
                {sort && sort.key === c.key ? (sort.dir === 'asc' ? ' ↑' : ' ↓') : ''}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {view.slice(0, limit).map((row, i) => {
            const k = rowKey ? rowKey(row, i) : i;
            return (
              <tr key={k} className={`${onRowClick ? 'click' : ''} ${selectedKey !== undefined && selectedKey === k ? 'sel' : ''}`} onClick={onRowClick ? () => onRowClick(row) : undefined}>
                {columns.map((c) => (
                  <td key={c.key} className={c.num ? 'num' : ''}>
                    {c.render ? c.render(row) : row[c.key] ?? '—'}
                  </td>
                ))}
              </tr>
            );
          })}
        </tbody>
      </table>
      {view.length === 0 && <Empty>no rows match “{filter}”</Empty>}
      {view.length > limit && <div className="tone-dim">showing {limit} of {view.length} — use the filter to narrow down</div>}
    </>
  );
}

// ------------------------------------------------------------------ Toast
export function Toast({ toast }) {
  if (!toast) return null;
  return <div className={`toast ${toast.error ? 'err' : ''}`}>{toast.text}</div>;
}
