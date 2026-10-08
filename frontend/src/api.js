// All backend calls live here, so components never deal with fetch() directly.
//
// Browser -> /api/v1/*  -> (Vite proxy in dev, Caddy in production) -> FastAPI :8000
// The proxy adds the Bearer token. The browser never holds an API token.
//
// Endpoints used (all documented in BACKEND_UI_SCOPE_AND_LIMITATIONS.md):
//   GET    /nodes                                   node inventory (legacy list)
//   POST   /nodes                                   register node            (admin)
//   DELETE /nodes/{id}                              deactivate node          (admin)
//   GET    /nodes/{id}/metrics/{category}/series    retention-bounded history (raw or time-bucketed);
//                                                   with limit=1 it doubles as "newest snapshot of one source"
//   (GET /nodes/{id}/metrics exists too, but returns up to 200 snapshots per category -> too heavy to poll)
//   GET    /nodes/{id}/collection-status            per category x source freshness
//   GET    /nodes/{id}/alerts | /alerts/active | /anomalies
//   GET    /events                                  fleet alert+anomaly feed (cursor paged)
//   GET    /logs                                    fleet log search (cursor paged)
//   GET    /investigations/search | POST /investigations
//   GET    /fleet/summary  /health/operations       fleet + pipeline health
const BASE = (import.meta.env.VITE_API_BASE || '') + '/api/v1';

export class ApiError extends Error {
  constructor(message, status) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

function readDetail(body) {
  if (!body) return '';
  const d = body.detail;
  if (typeof d === 'string') return d;
  if (Array.isArray(d)) return d.map((x) => x.msg || JSON.stringify(x)).join('; ');
  if (d && typeof d === 'object') return d.message || JSON.stringify(d);
  return '';
}

function friendly(status, detail) {
  if (status === 401) {
    return 'API token missing or wrong. Set PALANTIR_API_READ_TOKEN / PALANTIR_API_ADMIN_TOKEN in the repo .env (same values as the backend) and restart `npm run dev`.';
  }
  if (status === 403) {
    return detail || 'This action needs the admin token. Start the UI with PALANTIR_UI_ROLE=admin.';
  }
  if (status === 503 && /not configured|distinct/i.test(detail || '')) {
    return `Backend auth is not configured: ${detail}. Fill the API tokens in the backend .env and recreate the backend container.`;
  }
  return detail || '';
}

function qs(params) {
  const sp = new URLSearchParams();
  Object.entries(params || {}).forEach(([k, v]) => {
    if (v === null || v === undefined || v === '' || v === false) return;
    sp.set(k, String(v));
  });
  const s = sp.toString();
  return s ? `?${s}` : '';
}

async function request(path, options = {}, { base = BASE, signal } = {}) {
  let res;
  try {
    res = await fetch(base + path, {
      headers: { 'Content-Type': 'application/json' },
      signal,
      ...options,
    });
  } catch (err) {
    if (err && err.name === 'AbortError') throw err;
    throw new ApiError('Cannot reach the PALANTIR backend. Is it running (docker compose ps) on port 8000?', 0);
  }

  if (!res.ok) {
    let detail = '';
    try {
      detail = readDetail(await res.json());
    } catch (err) {
      // body was not JSON (Caddy "Read access required" text etc.)
    }
    const message =
      friendly(res.status, detail) ||
      (res.status >= 500
        ? `Backend error (${res.status}). Check \`docker compose logs backend\`.`
        : `Request failed (${res.status} ${res.statusText})`);
    throw new ApiError(message, res.status);
  }
  if (res.status === 204) return null;
  return res.json();
}

export const api = {
  // ---- nodes -------------------------------------------------------------
  listNodes: () => request('/nodes'),
  registerNode: (node) => request('/nodes', { method: 'POST', body: JSON.stringify(node) }),
  deleteNode: (id) => request(`/nodes/${id}`, { method: 'DELETE' }),
  getCollectionStatus: (id) => request(`/nodes/${id}/collection-status`),
  getCapabilities: (id) => request(`/nodes/${id}/capabilities`),

  // ---- telemetry ---------------------------------------------------------
  // Heavy: newest snapshot + up to 200 recent rows for all 8 categories. Not used for polling.
  getLatest: (id) => request(`/nodes/${id}/metrics`),
  // params: since, until (ISO with tz), source, limit (<=1000), cursor, bucket_seconds (10..86400)
  getSeries: (id, category, params) => request(`/nodes/${id}/metrics/${category}/series${qs(params)}`),

  // ---- alerts / anomalies --------------------------------------------------
  getActiveAlerts: (id) => request(`/nodes/${id}/alerts/active`),
  getAlerts: (id, limit = 100) => request(`/nodes/${id}/alerts${qs({ limit })}`),
  getAnomalies: (id, limit = 100) => request(`/nodes/${id}/anomalies${qs({ limit })}`),
  // params: event_type(all|alert|anomaly), node_id, severity, min_score, since, until, limit, cursor
  getEvents: (params) => request(`/events${qs(params)}`),

  // ---- logs ----------------------------------------------------------------
  // params: node_id, q, service, pid, source, severity, since, until, limit, cursor
  getLogs: (params) => request(`/logs${qs(params)}`),

  // ---- investigations -------------------------------------------------------
  // params: node_id, status, trigger_type, since, until, limit, cursor
  searchInvestigations: (params) => request(`/investigations/search${qs(params)}`),
  triggerInvestigation: (nodeId, triggerType = 'manual', triggerId = null) =>
    request('/investigations', {
      method: 'POST',
      body: JSON.stringify({ node_id: nodeId, trigger_type: triggerType, trigger_id: triggerId }),
    }),

  // ---- fleet / health --------------------------------------------------------
  getFleetSummary: () => request('/fleet/summary'),
  getOpsHealth: () => request('/health/operations'),
  getMetricSchema: () => request('/metrics/schema'),
  // Process liveness probe (not under /api/v1, not authenticated).
  healthz: () => request('/healthz', {}, { base: '' }),
};
