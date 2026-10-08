import { useEffect, useState } from 'react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { Badge, Box, Chips, Empty, ErrorLine, Spinner } from './ui';
import { CAN_WRITE } from '../lib/role';
import { severityTone } from '../lib/events';
import { formatAlertValue, formatDateTime, formatRelative, scoreToPercent } from '../lib/format';

function InvestigateBtn({ onInvestigate, type, id, existing }) {
  if (existing) {
    return <button className="btn sm" onClick={() => onInvestigate(null, null, existing)} title="Open the linked investigation">inv #{existing}</button>;
  }
  if (!CAN_WRITE) return null;
  return <button className="btn sm" onClick={() => onInvestigate(type, id)}>investigate</button>;
}

// ------------------------------------------------------------------ [1] active alerts (per node)
function ActiveAlerts({ state, onInvestigate }) {
  const list = (state.data && state.data.active) || [];
  const err = state.data && state.data.errors && state.data.errors.active;
  return (
    <Box n={1} title="active alerts" hot right={`${list.length} firing`}>
      {err && <ErrorLine>{err}</ErrorLine>}
      {list.length === 0 && !err ? (
        <Empty>No WARNING / CRITICAL alert is currently open on this node (latest transition per alert + chart).</Empty>
      ) : (
        list.map((a) => (
          <div key={a.id} className="row" style={{ padding: '1px 0', flexWrap: 'wrap' }}>
            <Badge tone={severityTone(a.status)}>{a.status}</Badge>
            <b>{a.alert_name}</b>
            <span className="tone-dim">{a.chart}</span>
            <span>{formatAlertValue(a.value, a.units)}</span>
            <span className="grow" />
            <span className="tone-dim" title={formatDateTime(a.received_at)}>{formatRelative(a.received_at)}</span>
            <InvestigateBtn onInvestigate={onInvestigate} type="alert" id={a.id} existing={a.investigation_id} />
          </div>
        ))
      )}
    </Box>
  );
}

// ------------------------------------------------------------------ [2] event feed (/events, cursor paged)
function EventFeed({ node, scope, setScope, onInvestigate, refreshMs }) {
  const [type, setType] = useState('all');
  const [severity, setSeverity] = useState('');
  const [more, setMore] = useState([]);
  const [loadingMore, setLoadingMore] = useState(false);
  const [moreError, setMoreError] = useState('');

  const params = { event_type: type, severity: type === 'anomaly' ? '' : severity, node_id: scope === 'node' && node ? node.id : '', limit: 100 };
  const key = JSON.stringify(params);
  const first = usePolling(() => api.getEvents(params), [key], refreshMs, true);
  useEffect(() => { setMore([]); setMoreError(''); }, [key]);

  const items = first.data ? first.data.items : [];
  const seen = new Set(items.map((e) => `${e.event_type}-${e.id}`));
  const all = items.concat(more.filter((e) => !seen.has(`${e.event_type}-${e.id}`)));
  const lastCursor = more.length > 0 ? more.cursor : first.data && first.data.next_cursor;
  const hasMore = more.length > 0 ? more.hasMore : first.data && first.data.has_more;

  async function loadMore() {
    setLoadingMore(true);
    setMoreError('');
    try {
      const page = await api.getEvents({ ...params, cursor: lastCursor });
      const merged = more.concat(page.items);
      merged.cursor = page.next_cursor;
      merged.hasMore = page.has_more;
      setMore(merged);
    } catch (err) {
      setMoreError(err.message);
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <Box
      n={2}
      title="events"
      controls={
        <>
          <Chips value={type} onChange={setType} options={[{ value: 'all', label: 'all' }, { value: 'alert', label: 'alerts' }, { value: 'anomaly', label: 'anomalies' }]} />
          {type !== 'anomaly' && (
            <select className="in" style={{ marginLeft: 6 }} value={severity} onChange={(e) => setSeverity(e.target.value)}>
              <option value="">any severity</option>
              <option value="CRITICAL">CRITICAL</option>
              <option value="WARNING">WARNING</option>
              <option value="CLEAR">CLEAR</option>
            </select>
          )}
          <Chips value={scope} onChange={setScope} options={[{ value: 'node', label: 'this node' }, { value: 'fleet', label: 'fleet' }]} />
        </>
      }
      right={`${all.length}${hasMore ? '+' : ''} events`}
    >
      {first.error && <ErrorLine>{first.error}</ErrorLine>}
      {first.loading && !first.data ? <Empty><Spinner /> loading…</Empty> : all.length === 0 ? (
        <Empty>No events match. Anomaly rows are only stored when two or more contexts cross the threshold — an empty list is not proof that nothing is anomalous.</Empty>
      ) : (
        <div className="box-scroll" style={{ maxHeight: 'calc(100vh - 330px)' }}>
          <table className="tbl">
            <thead>
              <tr><th>Time</th>{scope === 'fleet' && <th>Host</th>}<th>Type</th><th>Level</th><th>Detail</th><th /></tr>
            </thead>
            <tbody>
              {all.map((e) => (
                <tr key={`${e.event_type}-${e.id}`}>
                  <td className="tone-dim" title={formatRelative(e.occurred_at)}>{formatDateTime(e.occurred_at)}</td>
                  {scope === 'fleet' && <td>{e.hostname}</td>}
                  <td className={e.event_type === 'alert' ? 'tone-yellow' : 'tone-purple'}>{e.event_type}</td>
                  <td>
                    {e.event_type === 'alert' ? <Badge tone={severityTone(e.severity)}>{e.severity}</Badge> : <Badge tone="purple">{Math.round(scoreToPercent(e.max_score) || 0)}%</Badge>}
                  </td>
                  <td style={{ maxWidth: 560 }}>
                    {e.event_type === 'alert' ? (
                      <><b>{e.alert_name}</b> <span className="tone-dim">{e.chart}</span> {formatAlertValue(e.value, e.units)}</>
                    ) : (
                      <span title={JSON.stringify(e.scores)}>
                        {(e.contexts || []).slice(0, 4).map((c) => `${c} ${e.scores && e.scores[c] !== undefined ? `(${Math.round(scoreToPercent(e.scores[c]))}%)` : ''}`).join(' · ')}
                        {(e.contexts || []).length > 4 ? ` +${e.contexts.length - 4}` : ''}
                      </span>
                    )}
                  </td>
                  <td>
                    {(e.event_type === 'anomaly' || e.severity === 'WARNING' || e.severity === 'CRITICAL') && (
                      <InvestigateBtn onInvestigate={(t, id, existing) => onInvestigate(t, id, existing, e.node_id)} type={e.event_type} id={e.id} existing={e.investigation_id} />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {moreError && <ErrorLine>{moreError}</ErrorLine>}
          {hasMore && (
            <div style={{ padding: '6px 0' }}>
              <button className="btn" onClick={loadMore} disabled={loadingMore}>{loadingMore ? 'loading…' : 'load older events'}</button>
            </div>
          )}
        </div>
      )}
    </Box>
  );
}

export default function AlertsTab({ node, state, scope, setScope, onInvestigate, refreshMs }) {
  return (
    <div style={{ display: 'grid', gap: 14, marginTop: 6 }}>
      <ActiveAlerts state={state} onInvestigate={onInvestigate} />
      <EventFeed node={node} scope={scope} setScope={setScope} onInvestigate={onInvestigate} refreshMs={refreshMs} />
    </div>
  );
}
