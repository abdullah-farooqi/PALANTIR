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
