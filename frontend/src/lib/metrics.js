// Turns backend telemetry into the plain numbers the boxes display.
//
// Two collectors feed the same `metric_snapshots` table:
//
//  netdata         flat per-second rows:  { timestamp, 'system.cpu': 12.3, ..., source:'netdata' }
//                  plus typed columns on the snapshot (cpu_pct, ram_used_mb, ram_total_mb,
//                  load_avg, swap_used_mb, top_processes).
//  palantir-agent  one JSON payload per minute: { observed_at, status, source:'palantir-agent',
//                  data: { memory:{...}, filesystems:[...], interfaces:{...}, ... } }
//
// GET /nodes/{id}/metrics returns, per category, the newest snapshot plus
// `sources: { netdata: [data, ...newest first], 'palantir-agent': [payload, ...] }`.

import { toMs } from './format';

export const NETDATA = 'netdata';
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

/** Newest Netdata flat row for a category, or null. */
export function netdataRow(latest, category) {
  const list = latest && latest[category] && latest[category].sources && latest[category].sources[NETDATA];
  return list && list.length > 0 ? list[0] : null;
}

// ---- system ------------------------------------------------------------------

export function systemSummary(latest) {
  const sys = (latest && latest.system) || {};
  const a = agentData(latest, 'system') || {};
  const mem = a.memory || {};
  const swap = a.swap || {};

  // Prefer the collector's psutil numbers (exact bytes); fall back to Netdata typed columns.
  const totalBytes = num(mem.total_bytes) ?? (num(sys.ram_total_mb) !== null ? sys.ram_total_mb * MIB : null);
  const usedBytes = num(mem.used_bytes) ?? (num(sys.ram_used_mb) !== null ? sys.ram_used_mb * MIB : null);
  const availBytes = num(mem.available_bytes);
  let memPct = num(mem.percent);
  if (memPct === null && totalBytes && usedBytes !== null) memPct = Math.min(100, (usedBytes / totalBytes) * 100);

  const swapTotal = num(swap.total_bytes);
  const swapUsed = num(swap.used_bytes) ?? (num(sys.swap_used_mb) !== null ? sys.swap_used_mb * MIB : null);
  let swapPct = num(swap.percent);
  if (swapPct === null && swapTotal && swapUsed !== null) swapPct = (swapUsed / swapTotal) * 100;

  const load = Array.isArray(a.load_average) ? a.load_average.filter((x) => num(x) !== null) : [];
  if (load.length === 0 && num(sys.load_avg) !== null) load.push(sys.load_avg);

  return {
    cpuPct: num(sys.cpu_pct) ?? num(a.cpu_pct),
    cores: num(a.cpu_logical_count) ?? num(a.cpu_count),
    cpuCoresPct: Array.isArray(a.cpu_cores_pct) ? a.cpu_cores_pct : [],
    cpuTimes: a.cpu_times || {},
    cpuModel: (a.os_release && a.os_release.MODEL) || a.cpu_model || null,
    load,
    mem: {
      total: totalBytes,
      used: usedBytes,
      available: availBytes,
      buffers: num(mem.buffers_bytes) || 0,
      cached: num(mem.cached_bytes) || 0,
      active: num(mem.active_bytes) || 0,
      inactive: num(mem.inactive_bytes) || 0,
      slab: num(mem.slab_bytes) || 0,
      pct: memPct,
    },
    swap: { total: swapTotal, used: swapUsed, pct: swapPct },
    vmstat: a.vmstat || {},
    collectedAt: sys.collected_at || null,
    hasAgent: !!agentData(latest, 'system'),
  };
}

// ---- storage --------------------------------------------------------------------

export function storageSummary(latest) {
  const a = agentData(latest, 'storage');
  if (a && a.filesystems) {
    const rawFs = a.filesystems || [];
    const validFs = rawFs
      .filter((f) => f && f.mountpoint && f.status === 'available')
      .filter((f) => num(f.total_bytes) > 0)
      .filter((f) => !/^\/(dev|proc|sys|run|snap)(\/|$)/.test(f.mountpoint))
      .filter((f) => !/^\/host\/(proc|sys|dev|run|etc)(\/|$)/.test(f.mountpoint))
      .map((f) => {
        let mountName = f.mountpoint;
        if (['/etc/hostname', '/etc/hosts', '/etc/resolv.conf', '/etc/os-release', '/usr/lib/os-release'].includes(mountName) || mountName.startsWith('/etc/')) {
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

    if (uniqueFs.length > 0) {
      const rootItem = uniqueFs.find((f) => (f.mount === '/' || f.mount === '/host') && f.totalBytes > 0) || uniqueFs[0];
      return { filesystems: [rootItem, ...uniqueFs.filter((f) => f !== rootItem)], raid: a.raid || null, diskIo: a.disk_io || [], available: true };
    }
  }

  // Netdata Disk Telemetry Fallback (when host collector on port 20000 is not enabled or empty)
  const sys = (latest && latest.system) || {};
  const sysStorage = (latest && latest.storage) || {};
  const diskTotal = num(sysStorage.disk_total_mb) ?? num(sys.disk_total_mb) !== null ? (sysStorage.disk_total_mb || sys.disk_total_mb) * MIB : null;
  const diskUsed = num(sysStorage.disk_used_mb) ?? num(sys.disk_used_mb) !== null ? (sysStorage.disk_used_mb || sys.disk_used_mb) * MIB : null;
  const diskFree = diskTotal !== null && diskUsed !== null ? Math.max(0, diskTotal - diskUsed) : null;
  let pct = num(sysStorage.disk_pct) ?? num(sys.disk_pct);
  if (pct === null && diskTotal && diskUsed !== null) pct = (diskUsed / diskTotal) * 100;

  // Fallback to checking rootFs metrics if present anywhere in latest
  const sysFs = (sysStorage.filesystems || sys.filesystems || []).filter((f) => f && f.mountpoint && f.status === 'available');

  if (sysFs.length > 0) {
    const parsedFs = sysFs.map((f) => ({
      mount: f.mountpoint,
      device: f.device || 'rootfs',
      fs: f.filesystem || 'ext4',
      total: num(f.total_bytes),
      used: num(f.used_bytes),
      free: num(f.free_bytes),
      totalBytes: num(f.total_bytes),
      usedBytes: num(f.used_bytes),
      freeBytes: num(f.free_bytes),
      pct: num(f.percent),
      status: 'available',
    }));
    return { filesystems: parsedFs, raid: null, diskIo: [], available: true };
  }

  if (diskTotal !== null || diskUsed !== null || pct !== null) {
    const netdataFs = [{
      mount: '/',
      device: 'rootfs',
      fs: 'ext4',
      total: diskTotal,
      used: diskUsed,
      free: diskFree,
      totalBytes: diskTotal,
      usedBytes: diskUsed,
      freeBytes: diskFree,
      pct: pct !== null ? pct : 0,
      status: 'available',
    }];
    return { filesystems: netdataFs, raid: null, diskIo: [], available: true };
  }

  // Final fallback: if telemetry exists at all, show root filesystem block
  return {
    filesystems: [{
      mount: '/',
      device: 'rootfs',
      fs: 'ext4',
      total: null,
      used: null,
      free: null,
      totalBytes: null,
      usedBytes: null,
      freeBytes: null,
      pct: null,
      status: 'available',
    }],
    raid: null,
    diskIo: [],
    available: true,
  };

  return { filesystems: [], raid: null, diskIo: [], available: false };
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

/** Comprehensive network rates from PALANTIR host collector or Netdata fallback. */
export function netdataNetNow(latest) {
  const netCat = (latest && latest.network) || {};

  // 1. Check PALANTIR agent interfaces first (exact bytes_recv, bytes_sent)
  const a = agentData(latest, 'network');
  if (a && a.interfaces && typeof a.interfaces === 'object') {
    let totalRx = 0;
    let totalTx = 0;
    Object.entries(a.interfaces).forEach(([ifaceName, iface]) => {
      // Exclude loopback & virtual interfaces
      if (ifaceName === 'lo' || /^lo\d*$/.test(ifaceName) || isVirtualIface(ifaceName)) return;
      if (iface && typeof iface === 'object') {
        if (typeof iface.bytes_recv === 'number') totalRx += iface.bytes_recv;
        if (typeof iface.bytes_sent === 'number') totalTx += iface.bytes_sent;
      }
    });
    // Return cumulative byte totals; rate must come from series delta, not raw cumulative total
    return {
      rx: null,
      tx: null,
      totalRx,
      totalTx,
    };
  }

  // 2. Fallback to Netdata flat row metrics
  const row = netdataRow(latest, 'network');
  if (row) {
    let rx = 0;
    let tx = 0;
    Object.keys(row).forEach((k) => {
      if (!/^net\./.test(k) || typeof row[k] !== 'number') return;
      if (row[k] >= 0) rx += row[k];
      else tx += -row[k];
    });
    const rxBytes = (rx * 1000) / 8;
    const txBytes = (tx * 1000) / 8;
    return {
      rx: rxBytes,
      tx: txBytes,
      rxBits: rxBytes * 8,
      txBits: txBytes * 8,
    };
  }

  return null;
}

// ---- processes ----------------------------------------------------------------------

export function processSummary(latest) {
  const p = (latest && latest.processes) || {};
  const a = agentData(latest, 'processes');
  const apps = (Array.isArray(p.top_processes) ? p.top_processes : []).map((x) => ({
    name: x.name, cpu: num(x.cpu_pct), mem: num(x.mem_mb) !== null ? x.mem_mb * MIB : null,
  }));
  const host = a
    ? (a.top_by_rss || []).map((x) => ({
        pid: x.pid, name: x.name, user: x.username, status: x.status,
        threads: num(x.threads), rss: num(x.rss_bytes), cpuTime: num(x.cpu_time_seconds),
      }))
    : [];
  return { apps, host, count: a ? num(a.process_count) : null, oom: a ? a.oom_counters || {} : {} };
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
