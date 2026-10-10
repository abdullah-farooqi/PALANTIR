// Turns backend telemetry into the plain numbers the boxes display.
//
// The PALANTIR host collector ("palantir-agent") is the only telemetry source. Every helper here
// returns null / [] when the collector did not report a value - nothing is ever replaced by a
// made-up default (0, "ext4", a flat line ...). Screens turn null into "no data available".
//
// GET /nodes/{id}/metrics/{category}/series?source=palantir-agent returns snapshots shaped like
//   { collected_at, data: { observed_at, status, source, data: { ...collector fields } }, metrics:{typed} }

import { toMs } from './format';

export const AGENT = 'palantir-agent';
export const MIB = 1024 * 1024;

export const CATEGORIES = ['system', 'storage', 'network', 'services', 'processes', 'connections', 'containers', 'vms'];

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);

// ---- raw access ------------------------------------------------------------

/** Newest collector payload for a category, or null. */
export function agentPayload(latest, category) {
  const list = latest && latest[category] && latest[category].sources && latest[category].sources[AGENT];
  return list && list.length > 0 ? list[0] : null;
}

/** `data` object inside the newest collector payload (the useful part), or null. */
export function agentData(latest, category) {
  const p = agentPayload(latest, category);
  return p && p.data && typeof p.data === 'object' ? p.data : null;
}

export function agentStatus(latest, category) {
  const p = agentPayload(latest, category);
  return p ? p.status || 'available' : null;
}

// ---- system ------------------------------------------------------------------

export function systemSummary(latest) {
  const sys = (latest && latest.system) || {};
  const a = agentData(latest, 'system') || {};
  const mem = a.memory || {};
  const swap = a.swap || {};

  const totalBytes = num(mem.total_bytes);
  const usedBytes = num(mem.used_bytes);
  const availBytes = num(mem.available_bytes);
  let memPct = num(mem.percent);
  if (memPct === null && totalBytes && usedBytes !== null) memPct = Math.min(100, (usedBytes / totalBytes) * 100);

  const swapTotal = num(swap.total_bytes);
  const swapUsed = num(swap.used_bytes);
  let swapPct = num(swap.percent);
  if (swapPct === null && swapTotal && swapUsed !== null) swapPct = (swapUsed / swapTotal) * 100;

  const load = Array.isArray(a.load_average) ? a.load_average.filter((x) => num(x) !== null) : [];
  const cores = num(a.cpu_logical_count) ?? num(a.cpu_count);

  return {
    cpuPct: num(a.cpu_pct),
    cores,
    cpuCoresPct: Array.isArray(a.cpu_cores_pct) ? a.cpu_cores_pct.filter((x) => num(x) !== null) : [],
    cpuHistory: Array.isArray(a.cpu_history) ? a.cpu_history : [],
    cpuTimes: a.cpu_times || {},
    cpuModel: a.cpu_model || (a.os_release && a.os_release.MODEL) || null,
    load,
    mem: {
      total: totalBytes,
      used: usedBytes,
      available: availBytes,
      buffers: num(mem.buffers_bytes),
      cached: num(mem.cached_bytes),
      active: num(mem.active_bytes),
      inactive: num(mem.inactive_bytes),
      slab: num(mem.slab_bytes),
      pct: memPct,
    },
    swap: { total: swapTotal, used: swapUsed, pct: swapPct },
    vmstat: a.vmstat || {},
    collectedAt: sys.collected_at || null,
    hasAgent: !!agentData(latest, 'system'),
  };
}

// ---- storage --------------------------------------------------------------------

/** Disk throughput measured by the collector itself (needs no second snapshot). null when not measured. */
function ioNowFrom(devices) {
  const sum = (key) => {
    const values = devices.map((d) => num(d[key])).filter((v) => v !== null);
    return values.length ? values.reduce((x, y) => x + y, 0) : null;
  };
  const max = (key) => {
    const values = devices.map((d) => num(d[key])).filter((v) => v !== null);
    return values.length ? Math.max(...values) : null;
  };
  const read = sum('read_bytes_per_sec');
  const write = sum('write_bytes_per_sec');
  const r = sum('read_iops');
  const w = sum('write_iops');
  const totalOps = (r || 0) + (w || 0);
  const busy = max('busy_pct');
  return {
    readRate: read,
    writeRate: write,
    iops: r === null && w === null ? null : totalOps,
    busyPct: busy,
    totalOps: totalOps > 0 ? totalOps : null,
  };
}

export function storageSummary(latest) {
  const a = agentData(latest, 'storage');
  if (a && a.filesystems) {
    const rawFs = a.filesystems || [];
    const validFs = rawFs
      .filter((f) => f && f.mountpoint && f.status === 'available')
      .filter((f) => num(f.total_bytes) > 0)
      .filter((f) => !/^\/(dev|proc|sys|run|snap|app|usr\/lib)(\/|$)/.test(f.mountpoint))
      .filter((f) => !/^\/host\/(proc|sys|dev|run|etc)(\/|$)/.test(f.mountpoint))
      .filter((f) => !/\.[a-z0-9]+$/i.test(f.mountpoint))
      .map((f) => {
        let mountName = f.mountpoint;
        if (['/etc/hostname', '/etc/hosts', '/etc/resolv.conf', '/etc/os-release', '/usr/lib/os-release', '/app/collector.py'].includes(mountName) || mountName.startsWith('/etc/')) {
          mountName = '/';
        }
        return {
          mount: mountName,
          device: f.device,
          fs: f.filesystem,
          total: num(f.total_bytes),
          used: num(f.used_bytes),
          free: num(f.free_bytes),
          totalBytes: num(f.total_bytes),
          usedBytes: num(f.used_bytes),
          freeBytes: num(f.free_bytes),
          pct: num(f.percent),
          status: 'available',
        };
      })
      .sort((x, y) => (x.mount === '/' || x.mount === '/host' ? -1 : y.mount === '/' || y.mount === '/host' ? 1 : x.mount.localeCompare(y.mount)));

    // De-duplicate bind mounts pointing to the same underlying partition with identical capacity
    const uniqueFs = [];
    const seenMap = new Set();
    validFs.forEach((f) => {
      const key = `${f.totalBytes}-${f.usedBytes}`;
      if (!seenMap.has(key)) {
        seenMap.add(key);
        uniqueFs.push(f);
      }
    });

    // Filter disk_io to top-level block devices (exclude partitions like nvme0n1p1, vda1, zram, etc. when parent exists)
    const rawDiskIo = Array.isArray(a.disk_io) ? a.disk_io : [];
    const deviceNames = new Set(rawDiskIo.map((d) => d.device || d.name || '').filter(Boolean));
    const primaryDiskIo = rawDiskIo.filter((d) => {
      const dev = d.device || d.name || '';
      if (!dev) return false;
      if (/^(zram|loop|ram)/.test(dev)) return false;
      // If it's a partition (e.g. nvme0n1p1 or sda1) and its parent disk (nvme0n1 or sda) exists, skip partition
      const parentMatch = dev.match(/^([a-z]+|nvme\d+n\d+)p?\d+$/);
      if (parentMatch && parentMatch[1] !== dev && deviceNames.has(parentMatch[1])) {
        return false;
      }
      return true;
    });

    if (uniqueFs.length > 0) {
      const rootItem = uniqueFs.find((f) => (f.mount === '/' || f.mount === '/host') && f.totalBytes > 0) || uniqueFs[0];
      return { filesystems: [rootItem, ...uniqueFs.filter((f) => f !== rootItem)], raid: a.raid || null, diskIo: primaryDiskIo, ioNow: ioNowFrom(primaryDiskIo), available: true };
    }
  }

  return { filesystems: [], raid: null, diskIo: [], ioNow: null, available: false };
}

/**
 * Raw collector storage snapshots (/series?source=palantir-agent) -> disk I/O rates.
 * Calculates readRate (B/s), writeRate (B/s), and iops (ops/s) from time snapshot deltas.
 */
export function storageFromSeries(items) {
  const rows = (items || [])
    .map((it) => {
      const d = it && it.data && it.data.data;
      const io = d && d.disk_io;
      const t = toMs(it && it.data && it.data.observed_at) || toMs(it && it.collected_at);
      return Array.isArray(io) && t ? { t, io } : null;
    })
    .filter(Boolean)
    .sort((a, b) => a.t - b.t);

  if (rows.length < 2) {
    return { readRate: null, writeRate: null, iops: null };
  }

  const last = rows[rows.length - 1];
  const prev = rows[rows.length - 2];
  const dt = (last.t - prev.t) / 1000;
  if (dt <= 0) {
    return { readRate: null, writeRate: null, iops: null };
  }

  const filterPrimary = (ioList) => {
    const names = new Set(ioList.map((d) => d.device || d.name || '').filter(Boolean));
    return ioList.filter((d) => {
      const dev = d.device || d.name || '';
      if (!dev) return false;
      if (/^(zram|loop|ram)/.test(dev)) return false;
      const parentMatch = dev.match(/^([a-z]+|nvme\d+n\d+)p?\d+$/);
      if (parentMatch && parentMatch[1] !== dev && names.has(parentMatch[1])) {
        return false;
      }
      return true;
    });
  };

  const lastIo = filterPrimary(last.io);
  const prevMap = new Map();
  filterPrimary(prev.io).forEach((d) => {
    const key = d.device || d.name;
    if (key) prevMap.set(key, d);
  });

  let deltaReadBytes = 0;
  let deltaWriteBytes = 0;
  let deltaReadOps = 0;
  let deltaWriteOps = 0;

  lastIo.forEach((cur) => {
    const key = cur.device || cur.name;
    const old = prevMap.get(key);
    if (old) {
      if (typeof cur.read_bytes === 'number' && typeof old.read_bytes === 'number') {
        deltaReadBytes += Math.max(0, cur.read_bytes - old.read_bytes);
      }
      if (typeof cur.write_bytes === 'number' && typeof old.write_bytes === 'number') {
        deltaWriteBytes += Math.max(0, cur.write_bytes - old.write_bytes);
      }
      if (typeof cur.read_count === 'number' && typeof old.read_count === 'number') {
        deltaReadOps += Math.max(0, cur.read_count - old.read_count);
      }
      if (typeof cur.write_count === 'number' && typeof old.write_count === 'number') {
        deltaWriteOps += Math.max(0, cur.write_count - old.write_count);
      }
    }
  });

  return {
    readRate: deltaReadBytes / dt,
    writeRate: deltaWriteBytes / dt,
    iops: (deltaReadOps + deltaWriteOps) / dt,
  };
}

// ---- network ---------------------------------------------------------------------

const isLoopback = (name) => name === 'lo' || /^lo\d*$/.test(name);
// Docker/veth/bridge noise is hidden by default; "all" in the UI can still total everything.
export const isVirtualIface = (name) => /^(veth|vnet|br-|docker|virbr|cni|flannel|cali|tun|tap)/.test(name);

/**
 * Raw collector network snapshots (newest first, from /series?source=palantir-agent)
 * -> bandwidth history. Collector counters are cumulative, so rate = delta / delta-t.
 * Returns { points:[{t, rx, tx}], ifaces:{name:{rx,tx,totalRx,totalTx,errors,drops}}, names:[...] }
 */
export function networkFromSeries(items, selected = 'all') {
  const rows = (items || [])
    .map((it) => {
      const d = it && it.data && it.data.data;
      const ifs = d && d.interfaces;
      const t = toMs(it && it.data && it.data.observed_at) || toMs(it && it.collected_at);
      return ifs && t ? { t, ifs } : null;
    })
    .filter(Boolean)
    .sort((a, b) => a.t - b.t);

  const names = new Set();
  rows.forEach((r) => Object.keys(r.ifs).forEach((n) => names.add(n)));
  const physical = [...names].filter((n) => !isLoopback(n) && !isVirtualIface(n));
  const counted = selected === 'all' ? (physical.length ? physical : [...names].filter((n) => !isLoopback(n))) : [selected];

  const sum = (r, key) => counted.reduce((s, n) => s + (num(r.ifs[n] && r.ifs[n][key]) || 0), 0);

  const points = [];
  for (let i = 1; i < rows.length; i += 1) {
    const dt = (rows[i].t - rows[i - 1].t) / 1000;
    if (dt <= 0) continue;
    const rx = (sum(rows[i], 'bytes_recv') - sum(rows[i - 1], 'bytes_recv')) / dt;
    const tx = (sum(rows[i], 'bytes_sent') - sum(rows[i - 1], 'bytes_sent')) / dt;
    if (rx < 0 || tx < 0) continue; // counter reset (reboot)
    points.push({ t: rows[i].t, rx, tx });
  }

  const last = rows[rows.length - 1];
  const prev = rows[rows.length - 2];
  const ifaces = {};
  if (last) {
    Object.keys(last.ifs).forEach((n) => {
      const c = last.ifs[n] || {};
      let rx = null;
      let tx = null;
      if (prev && prev.ifs[n]) {
        const dt = (last.t - prev.t) / 1000;
        if (dt > 0) {
          rx = Math.max(0, (c.bytes_recv - prev.ifs[n].bytes_recv) / dt);
          tx = Math.max(0, (c.bytes_sent - prev.ifs[n].bytes_sent) / dt);
        }
      }
      ifaces[n] = {
        rx, tx,
        totalRx: num(c.bytes_recv), totalTx: num(c.bytes_sent),
        errors: (num(c.errors_in) || 0) + (num(c.errors_out) || 0),
        drops: (num(c.drops_in) || 0) + (num(c.drops_out) || 0),
      };
    });
  }
  const totals = last
    ? { totalRx: sum(last, 'bytes_recv'), totalTx: sum(last, 'bytes_sent') }
    : { totalRx: null, totalTx: null };
  return { points, ifaces, names: [...names].filter((n) => !isLoopback(n)), totals };
}

/**
 * Current network rates straight from the collector snapshot (counter deltas it measured itself).
 * Returns null when there is no network payload; rx/tx are null when no rate was measured yet.
 * Cumulative totals are returned as totalRx/totalTx and must never be shown as a speed.
 */
export function networkNow(latest) {
  const a = agentData(latest, 'network');
  if (!a || !a.interfaces || typeof a.interfaces !== 'object') return null;
  let rx = null;
  let tx = null;
  let totalRx = 0;
  let totalTx = 0;
  Object.entries(a.interfaces).forEach(([name, iface]) => {
    if (isLoopback(name) || isVirtualIface(name) || !iface || typeof iface !== 'object') return;
    if (num(iface.rx_bytes_per_sec) !== null) rx = (rx || 0) + iface.rx_bytes_per_sec;
    if (num(iface.tx_bytes_per_sec) !== null) tx = (tx || 0) + iface.tx_bytes_per_sec;
    totalRx += num(iface.bytes_recv) || 0;
    totalTx += num(iface.bytes_sent) || 0;
  });
  return { rx, tx, totalRx, totalTx };
}

// ---- processes ----------------------------------------------------------------------

export function processSummary(latest) {
  const a = agentData(latest, 'processes');
  const host = a
    ? (a.top_by_rss || []).map((x) => ({
        pid: x.pid, name: x.name, user: x.username, status: x.status,
        threads: num(x.threads), rss: num(x.rss_bytes), cpuTime: num(x.cpu_time_seconds),
        cpu: num(x.cpu_pct), // null = not measured yet (never shown as 0)
      }))
    : [];
  return { apps: [], host, count: a ? num(a.process_count) : null, oom: a ? a.oom_counters || {} : {} };
}

// ---- inventories -----------------------------------------------------------------------

export const listOf = (latest, category, key) => {
  const a = agentData(latest, category);
  return a && Array.isArray(a[key]) ? a[key] : [];
};

export const containerSources = (latest) => (agentData(latest, 'containers') || {}).sources || {};
export const vmSources = (latest) => (agentData(latest, 'vms') || {}).sources || {};

// ---- history --------------------------------------------------------------------------

/**
 * /series response items -> ascending [{t, v}] for one typed field.
 * Works for raw pages (items[].metrics.cpu_pct) and bucketed pages (items[].metrics.cpu_pct.avg).
 */
export function seriesToPoints(items, field) {
  const out = [];
  (items || []).forEach((it) => {
    const m = it && it.metrics && it.metrics[field];
    const v = typeof m === 'number' ? m : m && typeof m.avg === 'number' ? m.avg : null;
    const t = toMs(it.bucket_at || it.collected_at);
    if (v !== null && t) out.push({ t, v, max: m && typeof m.max === 'number' ? m.max : v });
  });
  return out.sort((a, b) => a.t - b.t);
}

/** Range presets for the history selector. `raw` = per-snapshot, otherwise server-side buckets. */
export const RANGES = [
  { key: '10m', label: '10m', ms: 10 * 60e3, raw: true, limit: 700 },
  { key: '1h', label: '1h', ms: 60 * 60e3, bucket: 30, limit: 500 },
  { key: '6h', label: '6h', ms: 6 * 60 * 60e3, bucket: 180, limit: 500 },
  { key: '24h', label: '24h', ms: 24 * 60 * 60e3 - 60e3, bucket: 600, limit: 500 },
];

export function seriesParams(range, extra = {}) {
  const until = Date.now();
  const p = { since: new Date(until - range.ms).toISOString(), limit: range.limit, ...extra };
  if (!range.raw) p.bucket_seconds = range.bucket;
  return p;
}

/** Quick helper for tables/graphs: clamp 0..max. */
export const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
