import { api } from '../api';
import { AGENT, CATEGORIES, seriesParams } from '../lib/metrics';
import { usePolling } from './usePolling';

const NET_MIN_MS = 30 * 60e3;
const NET_MAX_MS = 2 * 60 * 60e3;

// Inventory sections -> collector category that feeds them.
const SECTION_CATEGORY = { services: 'services', containers: 'containers', vms: 'vms', sockets: 'connections', storage: 'storage' };

/**
 * Which snapshots a view needs. We deliberately do NOT call GET /nodes/{id}/metrics:
 * it returns up to 200 snapshots per category and the `connections` category can hold
 * thousands of sockets per snapshot. Instead we ask /series for just the newest
 * snapshot (limit=1) of the categories on screen.
 */
function plan(view, section) {
  if (view === 'overview') return { agent: ['system', 'storage', 'processes', 'network'], cpu: true, net: true };
  if (view === 'inventory') return { agent: SECTION_CATEGORY[section] ? [SECTION_CATEGORY[section]] : [], cpu: false, net: false };
  return { agent: [], cpu: false, net: false };
}

function newest(nodeId, category, source) {
  return api
    // Let the API apply its configured retention window so stale hosts can still show
    // their most recent stored snapshot with its original collection timestamp.
    .getSeries(nodeId, category, { source, kind: 'full', limit: 1 })
    .then((r) => (r.items && r.items[0]) || null);
}

// Rebuilds the { category: { ...typed, sources:{'palantir-agent':[payload]} } } shape lib/metrics.js reads.
function assemble(agent) {
  const latest = {};
  CATEGORIES.forEach((cat) => {
    const entry = { sources: {} };
    const a = agent[cat];
    if (a) {
      Object.assign(entry, a.metrics || {});
      entry.collected_at = a.collected_at;
      entry.sources[AGENT] = [a.data];
    }
    latest[cat] = entry;
  });
  return latest;
}

/**
 * Everything one node's screens need, fetched in parallel (single failures don't blank the UI):
 *   latest   newest snapshots (see plan())              GET /nodes/{id}/metrics/{cat}/series?limit=1
 *   cpu      CPU history, raw or bucketed by `range`    GET /nodes/{id}/metrics/system/series
 *   net      collector counters -> bandwidth history    GET /nodes/{id}/metrics/network/series
 *   status   category x source freshness                GET /nodes/{id}/collection-status
 *   active   open WARNING/CRITICAL alerts               GET /nodes/{id}/alerts/active
 */
export function useNodeData(nodeId, range, refreshMs, view = 'overview', section = 'services') {
  return usePolling(
    async () => {
      const p = plan(view, section);
      const tasks = [];
      if (['overview', 'settings'].includes(view)) {
        tasks.push({ name: 'status', run: () => api.getCollectionStatus(nodeId) });
      }
      if (view === 'events') {
        tasks.push({ name: 'active', run: () => api.getActiveAlerts(nodeId) });
      }
      tasks.push(...p.agent.map((c) => ({ name: `agent:${c}`, run: () => newest(nodeId, c, AGENT) })));
      if (p.cpu) {
        tasks.push({
          name: 'cpu',
          // CPU history uses the collector's per-second samples, without mixing in full snapshots.
          run: () => api.getSeries(nodeId, 'system', seriesParams(range, { source: AGENT, kind: 'samples' })),
        });
      }
      if (p.net) {
        const netMs = Math.max(NET_MIN_MS, Math.min(range.ms, NET_MAX_MS));
        tasks.push({
          name: 'net',
          run: () => api.getSeries(nodeId, 'network', { source: AGENT, kind: 'full', limit: 120, since: new Date(Date.now() - netMs).toISOString() }),
        });
      }
      if (view === 'overview') {
        tasks.push({
          name: 'storageSeries',
          run: () => api.getSeries(nodeId, 'storage', { source: AGENT, kind: 'full', limit: 5 }),
        });
      }

      if (tasks.length === 0) {
        return { errors: {}, view, section, latest: assemble({}) };
      }

      const results = await Promise.allSettled(tasks.map((t) => t.run()));
      if (results.length && results.every((r) => r.status === 'rejected')) throw results[0].reason;

      const out = { errors: {}, view, section };
      const agent = {};
      results.forEach((r, i) => {
        const name = tasks[i].name;
        if (r.status === 'rejected') {
          out.errors[name] = r.reason && r.reason.message;
          return;
        }
        if (name.startsWith('agent:')) agent[name.slice(6)] = r.value;
        else out[name] = r.value;
      });
      out.latest = assemble(agent);
      return out;
    },
    [nodeId, range.key, view, view === 'inventory' ? section : ''],
    refreshMs,
    !!nodeId
  );
}

export async function fetchNodeSummary(nodeId) {
  if (!nodeId) return null;
  const categories = ['system', 'storage'];
  const since = new Date(Date.now() - 5 * 60e3).toISOString();
  const tasks = [
    ...categories.map((c) => newest(nodeId, c, AGENT)),
    // Two full network snapshots are enough to derive current bandwidth from real counters.
    api.getSeries(nodeId, 'network', { source: AGENT, kind: 'full', since, limit: 2 }),
    // The sparkline uses per-second samples only, not regular snapshots.
    api.getSeries(nodeId, 'system', { source: AGENT, kind: 'samples', since, limit: 300 }),
  ];
  const results = await Promise.allSettled(tasks);
  const agent = {};
  categories.forEach((cat, idx) => {
    const res = results[idx];
    if (res.status === 'fulfilled' && res.value) agent[cat] = res.value;
  });
  const networkRes = results[categories.length];
  const networkHistory = networkRes.status === 'fulfilled' ? networkRes.value?.items || [] : [];
  const cpuSeriesRes = results[categories.length + 1];
  const cpuItems = (cpuSeriesRes && cpuSeriesRes.status === 'fulfilled' && cpuSeriesRes.value && cpuSeriesRes.value.items) ? cpuSeriesRes.value.items : [];
  return { latest: assemble(agent), history: cpuItems, networkHistory };
}
