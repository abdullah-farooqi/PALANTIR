import assert from 'node:assert/strict';
import test from 'node:test';
import { api } from '../src/api.js';
import { AGENT, networkFromSeries, systemSummary } from '../src/lib/metrics.js';

function mockFetch(t, body) {
  const previousFetch = globalThis.fetch;
  const calls = [];
  globalThis.fetch = async (input, options = {}) => {
    calls.push({ url: String(input), options });
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { 'Content-Type': 'application/json' },
    });
  };
  t.after(() => { globalThis.fetch = previousFetch; });
  return calls;
}

test('system summary reads typed collector fields and leaves absent metrics unavailable', () => {
  const summary = systemSummary({
    system: {
      collected_at: '2026-11-15T14:00:00Z',
      sources: {
        [AGENT]: [{
          status: 'available',
          data: {
            cpu_pct: 37.5,
            cpu_logical_count: 8,
            memory: { total_bytes: 8_000, used_bytes: 5_000 },
          },
        }],
      },
    },
  });

  assert.equal(summary.cpuPct, 37.5);
  assert.equal(summary.cores, 8);
  assert.equal(summary.mem.pct, 62.5);
  assert.equal(summary.hasAgent, true);

  const missing = systemSummary({});
  assert.equal(missing.cpuPct, null);
  assert.equal(missing.mem.pct, null);
  assert.equal(missing.hasAgent, false);
});

test('network history derives physical-interface bandwidth from full snapshots', () => {
  const snapshot = (collectedAt, ethRx, ethTx) => ({
    collected_at: collectedAt,
    data: {
      observed_at: collectedAt,
      data: {
        interfaces: {
          eth0: { bytes_recv: ethRx, bytes_sent: ethTx },
          lo: { bytes_recv: 50_000, bytes_sent: 50_000 },
          veth123: { bytes_recv: 80_000, bytes_sent: 80_000 },
        },
      },
    },
  });
  const series = networkFromSeries([
    snapshot('2026-11-15T14:00:01Z', 2_500, 1_800),
    snapshot('2026-11-15T14:00:00Z', 1_000, 800),
  ]);

  assert.deepEqual(series.points.map(({ rx, tx }) => ({ rx, tx })), [{ rx: 1_500, tx: 1_000 }]);
  assert.deepEqual(series.names, ['eth0', 'veth123']);
});

test('getSeries calls the telemetry series route with source, kind, time window, and limit', async (t) => {
  const calls = mockFetch(t, { items: [] });
  await api.getSeries(17, 'system', {
    source: AGENT,
    kind: 'samples',
    limit: 300,
    since: '2026-11-15T13:55:00.000Z',
    omitted: '',
  });

  assert.equal(calls.length, 1);
  const url = new URL(calls[0].url, 'http://ui.local');
  assert.equal(url.pathname, '/api/v1/nodes/17/metrics/system/series');
  assert.equal(url.searchParams.get('source'), AGENT);
  assert.equal(url.searchParams.get('kind'), 'samples');
  assert.equal(url.searchParams.get('limit'), '300');
  assert.equal(url.searchParams.get('since'), '2026-11-15T13:55:00.000Z');
  assert.equal(url.searchParams.has('omitted'), false);
});

test('active alerts use the node alert endpoint and preserve its array response', async (t) => {
  const alerts = [{ id: 42, status: 'WARNING', alert_name: 'cpu', value: 91 }];
  const calls = mockFetch(t, alerts);
  const response = await api.getActiveAlerts(17);

  assert.deepEqual(response, alerts);
  assert.equal(new URL(calls[0].url, 'http://ui.local').pathname, '/api/v1/nodes/17/alerts/active');
});

test('fleet and operational summaries use their existing backend routes', async (t) => {
  const calls = mockFetch(t, {});
  await Promise.all([api.getFleetSummary(), api.getOpsHealth()]);

  assert.deepEqual(
    calls.map(({ url }) => new URL(url, 'http://ui.local').pathname).sort(),
    ['/api/v1/fleet/summary', '/api/v1/health/operations']
  );
});

test('manual telemetry ingest queues the admin fleet refresh endpoint', async (t) => {
  const calls = mockFetch(t, { status: 'queued', task_id: 'manual-refresh-task' });
  const result = await api.triggerIngest();

  assert.equal(result.task_id, 'manual-refresh-task');
  assert.equal(new URL(calls[0].url, 'http://ui.local').pathname, '/api/v1/fleet/refresh');
  assert.equal(calls[0].options.method, 'POST');
});

test('fleet telemetry and investigation analysis use their persisted API routes', async (t) => {
  const calls = mockFetch(t, { items: [] });
  await Promise.all([
    api.getFleetTelemetry(8),
    api.getInvestigationAnalysisRuns(31),
    api.getInvestigationAnalysisDetail(31, 'run-a', false),
    api.getInvestigationAnalysisCollection(31, 'run-a', 'iocs', { is_allowlisted: false, limit: 25 }),
  ]);

  const urls = calls.map(({ url }) => new URL(url, 'http://ui.local'));
  assert.deepEqual(urls.map((url) => url.pathname), [
    '/api/v1/fleet/telemetry',
    '/api/v1/investigations/31/analysis',
    '/api/v1/investigations/31/analysis/run-a',
    '/api/v1/investigations/31/analysis/run-a/collections/iocs',
  ]);
  assert.equal(urls[0].searchParams.get('limit'), '8');
  assert.equal(urls[2].searchParams.get('include_records'), 'false');
  assert.equal(urls[3].searchParams.get('is_allowlisted'), 'false');
  assert.equal(urls[3].searchParams.get('limit'), '25');
});

test('PCAP status, manual snapshots, retries, and downloads use authorized API routes', async (t) => {
  const calls = mockFetch(t, { status: 'queued' });
  await Promise.all([
    api.getNodeCaptureStatus(17),
    api.startNodeCapture(17),
    api.stopNodeCapture(17),
    api.captureInvestigationEvidence(31),
    api.retryInvestigationEvidenceTransfer(31, 12),
    api.getInvestigationEvidence(31),
  ]);

  const requests = calls.map(({ url, options }) => ({
    path: new URL(url, 'http://ui.local').pathname,
    method: options.method || 'GET',
  }));
  assert.deepEqual(requests, [
    { path: '/api/v1/nodes/17/capture/status', method: 'GET' },
    { path: '/api/v1/nodes/17/capture/start', method: 'POST' },
    { path: '/api/v1/nodes/17/capture/stop', method: 'POST' },
    { path: '/api/v1/investigations/31/evidence/capture', method: 'POST' },
    { path: '/api/v1/investigations/31/evidence/12/retry', method: 'POST' },
    { path: '/api/v1/investigations/31/evidence', method: 'GET' },
  ]);
  assert.equal(
    new URL(api.investigationEvidenceDownloadUrl(31, 12), 'http://ui.local').pathname,
    '/api/v1/investigations/31/evidence/12/download',
  );
});
