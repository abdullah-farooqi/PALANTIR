import { useEffect, useState } from 'react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { useDebounced } from '../hooks/useDebounced';
import { Box, Chips, Empty, ErrorLine, Spinner } from './ui';
import { logTone } from '../lib/events';
import { formatTime, formatDateTime } from '../lib/format';

const SEVERITIES = ['', 'error', 'warning', 'notice', 'info', 'debug'];

export default function LogsTab({ node, scope, setScope, refreshMs }) {
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
    q: dq, service: ds, severity, limit: 200,
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
      // surfaced through the banner below
      setMoreMeta({ next_cursor: cursor, has_more: true, error: err.message });
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <Box
      n={4}
      title="logs"
      hot
      controls={
        <>
          <input className="in" style={{ width: 200, marginLeft: 4 }} placeholder="search message…" value={q} onChange={(e) => setQ(e.target.value)} />
          <input className="in" style={{ width: 120, marginLeft: 4 }} placeholder="service" value={service} onChange={(e) => setService(e.target.value)} />
          <select className="in" style={{ marginLeft: 4 }} value={severity} onChange={(e) => setSeverity(e.target.value)}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s || 'any level'}</option>)}
          </select>
          <Chips value={scope} onChange={setScope} options={[{ value: 'node', label: 'this node' }, { value: 'fleet', label: 'fleet' }]} />
          <Chips value={paused ? 'p' : 'l'} onChange={(v) => setPaused(v === 'p')} options={[{ value: 'l', label: 'live' }, { value: 'p', label: 'paused' }]} />
        </>
      }
      right={`${all.length}${hasMore ? '+' : ''} lines • keep ${first.data ? first.data.retention_days : '?'}d`}
    >
      {first.error && <ErrorLine>{first.error}</ErrorLine>}
      {moreMeta && moreMeta.error && <ErrorLine>{moreMeta.error}</ErrorLine>}
      {first.loading && !first.data ? <Empty><Spinner /> loading…</Empty> : all.length === 0 ? (
        <Empty>No log events. Logs come from the host collector (journald + configured files); an empty list can also mean the collector is not enrolled for this node.</Empty>
      ) : (
        <div className="box-scroll" style={{ maxHeight: 'calc(100vh - 190px)' }}>
          {all.map((e) => (
            <div key={e.id}>
              <div className="logline" style={{ cursor: 'pointer' }} onClick={() => setOpen(open === e.id ? null : e.id)}>
                <span className="tone-dim" title={formatDateTime(e.event_at)}>{formatTime(e.event_at)}</span>
                <span className="tone-dim">{scope === 'fleet' ? e.hostname : e.source}</span>
                <span className={`tone-${logTone(e.severity)}`}>{e.severity || '—'}</span>
                <span className="tone-cyan">{e.service || '—'}{e.pid ? `[${e.pid}]` : ''}</span>
                <span className="msg">{e.message}</span>
              </div>
              {open === e.id && <pre className="pre" style={{ margin: '2px 0 6px' }}>{JSON.stringify({ source: e.source, parser: e.parser, fields: e.fields }, null, 2)}</pre>}
            </div>
          ))}
          {hasMore && (
            <div style={{ padding: '6px 0' }}>
              <button className="btn" onClick={loadMore} disabled={loadingMore}>{loadingMore ? 'loading…' : 'load older lines'}</button>
            </div>
          )}
        </div>
      )}
    </Box>
  );
}
