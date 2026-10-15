import { useEffect, useState } from 'react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { useDebounced } from '../hooks/useDebounced';
import { Badge, Box, Chips, Empty, ErrorLine, Spinner } from './ui';
import NodeHeaderNav from './NodeHeaderNav';
import { logTone } from '../lib/events';
import { formatTime, formatDateTime } from '../lib/format';

const SEVERITIES = [
  { value: '', label: 'ANY SEVERITY' },
  { value: 'error', label: 'ERROR' },
  { value: 'warning', label: 'WARNING' },
  { value: 'notice', label: 'NOTICE' },
  { value: 'info', label: 'INFO' },
  { value: 'debug', label: 'DEBUG' },
];

export default function LogsTab({ node, scope, setScope, refreshMs, onBack, onChangeView }) {
  const [q, setQ] = useState('');
  const [service, setService] = useState('');
  const [severity, setSeverity] = useState('');
  const [paused, setPaused] = useState(false);
  const [more, setMore] = useState([]);
  const [moreMeta, setMoreMeta] = useState(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [open, setOpen] = useState(null);
  const dq = useDebounced(q);
  const ds = useDebounced(service);

  const params = {
    node_id: scope === 'node' && node ? node.id : '',
    q: dq,
    service: ds,
    severity,
    limit: 200,
  };
  const key = JSON.stringify(params);
  const first = usePolling(() => api.getLogs(params), [key], refreshMs, !paused);
  useEffect(() => { setMore([]); setMoreMeta(null); setOpen(null); }, [key]);

  const items = first.data ? first.data.items : [];
  const seen = new Set(items.map((e) => e.id));
  const all = items.concat(more.filter((e) => !seen.has(e.id)));
  const cursor = moreMeta ? moreMeta.next_cursor : first.data && first.data.next_cursor;
  const hasMore = moreMeta ? moreMeta.has_more : first.data && first.data.has_more;

  async function loadMore() {
    setLoadingMore(true);
    try {
      const page = await api.getLogs({ ...params, cursor });
      setMore((m) => m.concat(page.items));
      setMoreMeta({ next_cursor: page.next_cursor, has_more: page.has_more });
    } catch (err) {
      setMoreMeta({ next_cursor: cursor, has_more: true, error: err.message });
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <>
      <NodeHeaderNav
        node={node}
        currentView="logs"
        onViewChange={onChangeView}
        onBack={onBack}
      />

      {/* Main Logs Panel */}
      <Box
        n={4}
        title="STRUCTURED SYSTEM LOGS"
        hot
        controls={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
            <input
              className="in"
              style={{
                width: 190,
                background: '#040805',
                border: '1px solid #1a3821',
                borderRadius: 6,
                padding: '2px 8px',
                fontSize: 11.5,
                color: '#d8dee9',
                outline: 'none',
                fontFamily: 'JetBrains Mono, monospace',
              }}
              placeholder="search message..."
              value={q}
              onChange={(e) => setQ(e.target.value)}
            />
            <input
              className="in"
              style={{
                width: 120,
                background: '#040805',
                border: '1px solid #1a3821',
                borderRadius: 6,
                padding: '2px 8px',
                fontSize: 11.5,
                color: '#d8dee9',
                outline: 'none',
                fontFamily: 'JetBrains Mono, monospace',
              }}
              placeholder="service..."
              value={service}
              onChange={(e) => setService(e.target.value)}
            />
            <select
              className="in"
              style={{
                background: '#040805',
                border: '1px solid #1a3821',
                borderRadius: 6,
                padding: '2px 8px',
                fontSize: 11.5,
                color: '#d8dee9',
                outline: 'none',
                fontFamily: 'JetBrains Mono, monospace',
              }}
              value={severity}
              onChange={(e) => setSeverity(e.target.value)}
            >
              {SEVERITIES.map((s) => (
                <option key={s.value} value={s.value}>
                  {s.label}
                </option>
              ))}
            </select>
            <Chips
              value={scope}
              onChange={setScope}
              options={[
                { value: 'node', label: 'THIS NODE' },
                { value: 'fleet', label: 'FLEET' },
              ]}
            />
            <Chips
              value={paused ? 'p' : 'l'}
              onChange={(v) => setPaused(v === 'p')}
              options={[
                { value: 'l', label: 'LIVE' },
                { value: 'p', label: 'PAUSED' },
              ]}
            />
          </div>
        }
        right={
          <span
            style={{
              background: 'rgba(18, 38, 22, 0.8)',
              border: '1px solid #1c4524',
              borderRadius: 5,
              padding: '2px 8px',
              color: '#39e569',
              fontWeight: 700,
              fontSize: 11,
              fontFamily: 'JetBrains Mono, monospace',
            }}
          >
            {all.length}{hasMore ? '+' : ''} lines • keep {first.data ? first.data.retention_days : '?'}d
          </span>
        }
      >
        {first.error && <ErrorLine>{first.error}</ErrorLine>}
        {moreMeta && moreMeta.error && <ErrorLine>{moreMeta.error}</ErrorLine>}
        {first.loading && !first.data ? (
          <Empty><Spinner /> streaming system journal…</Empty>
        ) : all.length === 0 ? (
          <div
            style={{
              background: 'rgba(6, 12, 8, 0.6)',
              border: '1px solid #142e1a',
              borderRadius: 8,
              padding: '16px 18px',
              color: '#728c78',
              fontSize: 12,
              lineHeight: 1.6,
            }}
          >
            <div style={{ color: '#a3c4aa', fontWeight: 700, marginBottom: 4 }}>
              No log events found.
            </div>
            <div>
              Logs are pulled via systemd journald and application log files by the host collector.
            </div>
          </div>
        ) : (
          <div
            className="box-scroll"
            style={{
              maxHeight: 'calc(100vh - 210px)',
              border: '1px solid #142e1a',
              borderRadius: 8,
              background: 'rgba(6, 12, 8, 0.6)',
              overflowY: 'auto',
              marginTop: 4,
            }}
          >
            <table className="tbl">
              <thead>
                <tr>
                  <th style={{ width: 100 }}>TIME</th>
                  <th style={{ width: 110 }}>{scope === 'fleet' ? 'HOST' : 'SOURCE'}</th>
                  <th style={{ width: 90 }}>LEVEL</th>
                  <th style={{ width: 170 }}>SERVICE [PID]</th>
                  <th>MESSAGE</th>
                </tr>
              </thead>
              <tbody>
                {all.map((e) => {
                  const tone = logTone(e.severity);
                  const isErr = tone === 'red';
                  const isWarn = tone === 'yellow';
                  const sevBg = isErr
                    ? 'rgba(239, 68, 68, 0.15)'
                    : isWarn
                    ? 'rgba(245, 158, 11, 0.15)'
                    : 'rgba(34, 211, 238, 0.12)';
                  const sevBorder = isErr ? '#ef4444' : isWarn ? '#f59e0b' : '#06b6d4';
                  const sevColor = isErr ? '#f87171' : isWarn ? '#fbbf24' : '#22d3ee';

                  return (
                    <tr
                      key={e.id}
                      onClick={() => setOpen(open === e.id ? null : e.id)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td style={{ color: '#94a3b8', fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5 }} title={formatDateTime(e.event_at)}>
                        {formatTime(e.event_at)}
                      </td>
                      <td style={{ color: '#a3c4aa', fontWeight: 600, fontFamily: 'JetBrains Mono, monospace', fontSize: 11 }}>
                        {scope === 'fleet' ? e.hostname : e.source}
                      </td>
                      <td>
                        <span
                          style={{
                            background: sevBg,
                            border: `1px solid ${sevBorder}`,
                            color: sevColor,
                            fontWeight: 700,
                            fontSize: 10.5,
                            padding: '1px 6px',
                            borderRadius: 4,
                            textTransform: 'uppercase',
                            letterSpacing: '0.03em',
                          }}
                        >
                          {e.severity || '—'}
                        </span>
                      </td>
                      <td>
                        <span style={{ color: '#06b6d4', fontWeight: 600, fontFamily: 'JetBrains Mono, monospace', fontSize: 11.5 }}>
                          {e.service || '—'}
                          {e.pid ? <span style={{ color: '#728c78' }}>[{e.pid}]</span> : ''}
                        </span>
                      </td>
                      <td style={{ wordBreak: 'break-word', whiteSpace: 'pre-wrap', color: '#d8dee9', fontSize: 12 }}>
                        {e.message}
                        {open === e.id && (
                          <div
                            style={{
                              marginTop: 8,
                              marginBottom: 4,
                              background: '#040805',
                              border: '1px solid #1b3d24',
                              borderRadius: 6,
                              padding: '8px 12px',
                            }}
                          >
                            <div style={{ color: '#39e569', fontSize: 11, fontWeight: 700, marginBottom: 4 }}>
                              RAW STRUCTURED LOG PAYLOAD
                            </div>
                            <pre className="pre" style={{ margin: 0, maxHeight: 220, fontSize: 11.5 }}>
                              {JSON.stringify({ source: e.source, parser: e.parser, fields: e.fields }, null, 2)}
                            </pre>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>

            {hasMore && (
              <div style={{ padding: '10px 14px', borderTop: '1px solid #142e1a', display: 'flex', justifyContent: 'center' }}>
                <button
                  className="btn primary sm"
                  onClick={loadMore}
                  disabled={loadingMore}
                  style={{ padding: '5px 16px', fontSize: 12 }}
                >
                  {loadingMore ? 'loading older log lines…' : 'Load Older Log Lines'}
                </button>
              </div>
            )}
          </div>
        )}
      </Box>
    </>
  );
}
