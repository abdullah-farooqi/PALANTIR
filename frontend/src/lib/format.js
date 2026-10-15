// Time and unit formatting helpers.
// Dates are shown in the browser's local time zone, 24-hour clock.

const LOCALE = 'en-GB';
const timeFmt = new Intl.DateTimeFormat(LOCALE, { hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23' });
const dateTimeFmt = new Intl.DateTimeFormat(LOCALE, {
  day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
});
const dayTimeFmt = new Intl.DateTimeFormat(LOCALE, {
  weekday: 'short', day: '2-digit', month: '2-digit',
});

// Accepts ISO strings, Date objects, or unix timestamps (seconds or milliseconds).
// ISO strings without a time zone are treated as UTC (the backend stores UTC).
export function toMs(value) {
  if (value === null || value === undefined || value === '') return null;
  if (value instanceof Date) {
    const t = value.getTime();
    return Number.isNaN(t) ? null : t;
  }
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) return null;
    return value < 1e11 ? value * 1000 : value;
  }
  if (typeof value === 'string') {
    let text = value.trim().replace(' ', 'T');
    if (/^\d+(\.\d+)?$/.test(text)) return toMs(Number(text));
    text = text.replace(/(\.\d{3})\d+/, '$1');
    if (/^\d{4}-\d{2}-\d{2}T[\d:.]+$/.test(text)) text += 'Z';
    const t = Date.parse(text);
    return Number.isNaN(t) ? null : t;
  }
  return null;
}

export function formatTime(value) {
  const ms = toMs(value);
  return ms === null ? '—' : timeFmt.format(new Date(ms));
}
export function formatDateTime(value) {
  const ms = toMs(value);
  return ms === null ? '—' : dateTimeFmt.format(new Date(ms));
}
export function formatClock(ms = Date.now()) {
  return `${timeFmt.format(new Date(ms))} • ${dayTimeFmt.format(new Date(ms)).replace(',', '')}`;
}

export function formatRelative(value, now = Date.now()) {
  const ms = toMs(value);
  if (ms === null) return '—';
  const s = Math.max(0, Math.floor((now - ms) / 1000));
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
}

export function formatDuration(ms) {
  if (ms === null || ms === undefined || ms < 0) return '—';
  const s = Math.floor(ms / 1000);
  if (s < 1) return '<1s';
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ${s % 60}s`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ${m % 60}m`;
  return `${Math.floor(h / 24)}d ${h % 24}h`;
}

// ---------------------------------------------------------------- numbers & units

export function formatNumber(value, maxDigits = 2) {
  if (value === null || value === undefined || !Number.isFinite(Number(value))) return '—';
  return Number(value).toLocaleString('en-US', { maximumFractionDigits: maxDigits });
}

// Fewer decimals for bigger numbers: 1234 -> "1,234", 12.34 -> "12.3", 1.234 -> "1.23"
export function smart(n) {
  const a = Math.abs(n);
  return formatNumber(n, a >= 100 ? 0 : a >= 10 ? 1 : 2);
}

export function formatPercent(v, digits = 0) {
  if (v === null || v === undefined || !Number.isFinite(Number(v))) return '—';
  return `${Number(v).toFixed(digits)}%`;
}

const DEC_UNITS = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
export function formatBytes(bytes) {
  if (bytes === null || bytes === undefined || !Number.isFinite(Number(bytes))) return '—';
  let v = Number(bytes);
  let i = 0;
  while (Math.abs(v) >= 1000 && i < DEC_UNITS.length - 1) {
    v /= 1000;
    i += 1;
  }
  return `${i === 0 ? Math.round(v) : v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${DEC_UNITS[i]}`;
}

// Network / disk speed formatting. The input is ALWAYS bytes per second.
export function formatNetworkSpeed(bytesPerSec) {
  if (bytesPerSec === null || bytesPerSec === undefined || !Number.isFinite(Number(bytesPerSec))) return '—';
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s'];
  let v = Number(bytesPerSec);
  let i = 0;
  while (v >= 1000 && i < units.length - 1) {
    v /= 1000;
    i += 1;
  }

  if (i === 0) return `${Math.round(v)} ${units[i]}`;
  return `${v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${units[i]}`;
}

export const formatRate = formatNetworkSpeed;

// bytes/s -> "11.7 Kibps" (bit rate, like btop)
export function formatBits(bytesPerSec) {
  if (bytesPerSec === null || bytesPerSec === undefined || !Number.isFinite(Number(bytesPerSec))) return '—';
  const units = ['bps', 'Kibps', 'Mibps', 'Gibps', 'Tibps'];
  let v = Number(bytesPerSec) * 8;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)} ${units[i]}`;
}

export function formatCount(n) {
  if (n === null || n === undefined || !Number.isFinite(Number(n))) return '—';
  return Number(n).toLocaleString('en-US');
}

export function formatAlertValue(value, units) {
  if (value === null || value === undefined) return '—';
  const text = smart(Number(value));
  if (!units) return text;
  return units === '%' ? `${text}%` : `${text} ${units}`;
}

// Anomaly scores may arrive as a ratio (0-1) or already as a percentage (0-100).
export function scoreToPercent(score) {
  const n = Number(score);
  if (!Number.isFinite(n)) return null;
  return n <= 1 ? n * 100 : n;
}

export function truncate(text, n = 40) {
  const s = String(text ?? '');
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}
