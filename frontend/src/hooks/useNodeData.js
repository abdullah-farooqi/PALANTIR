import { api } from '../api';
import { AGENT, CATEGORIES, seriesParams } from '../lib/metrics';
import { usePolling } from './usePolling';

const NET_MIN_MS = 30 * 60e3;
const NET_MAX_MS = 2 * 60 * 60e3;
const LATEST_WINDOW_MS = 20 * 60e3; // "latest" = newest snapshot inside the last 20 minutes

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
    .getSeries(nodeId, category, { source, kind: 'full', limit: 1, since: new Date(Date.now() - LATEST_WINDOW_MS).toISOString() })
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
      const tasks = [
        { name: 'status', run: () => api.getCollectionStatus(nodeId) },
        { name: 'active', run: () => api.getActiveAlerts(nodeId) },
        ...p.agent.map((c) => ({ name: `agent:${c}`, run: () => newest(nodeId, c, AGENT) })),
      ];
      if (p.cpu) {
        tasks.push({
          name: 'cpu',
          // per-second samples + the once-a-minute snapshots, raw for short ranges, bucketed for long ones
          run: () => api.getSeries(nodeId, 'system', seriesParams(range, { source: AGENT })),
        });
      }
      if (p.net) {
        const netMs = Math.max(NET_MIN_MS, Math.min(range.ms, NET_MAX_MS));
        tasks.push({
          name: 'net',
          run: () => api.getSeries(nodeId, 'network', { source: AGENT, limit: 120, since: new Date(Date.now() - netMs).toISOString() }),
        });
      }
      if (view === 'overview') {
        tasks.push({
          name: 'storageSeries',
          run: () => api.getSeries(nodeId, 'storage', { source: AGENT, limit: 5 }),
        });
      }

      const results = await Promise.allSettled(tasks.map((t) => t.run()));
      if (results.every((r) => r.status === 'rejected')) throw results[0].reason;

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
  const categories = ['system', 'storage', 'processes', 'network'];
  const tasks = [
    ...categories.map((c) => newest(nodeId, c, AGENT)),
    // last ~5 minutes of CPU (per-second rows) for the card sparkline
    api.getSeries(nodeId, 'system', { source: AGENT, since: new Date(Date.now() - 5 * 60e3).toISOString(), limit: 300 }),
  ];
  const results = await Promise.allSettled(tasks);
  const agent = {};
  categories.forEach((cat, idx) => {
    const res = results[idx];
    if (res.status === 'fulfilled' && res.value) agent[cat] = res.value;
  });
  const cpuSeriesRes = results[categories.length];
  const cpuItems = (cpuSeriesRes && cpuSeriesRes.status === 'fulfilled' && cpuSeriesRes.value && cpuSeriesRes.value.items) ? cpuSeriesRes.value.items : [];
  return { latest: assemble(agent), history: cpuItems };
}
