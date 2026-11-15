import { useMemo } from 'react';
import { Activity, AlertTriangle, ArrowRight, CircleDot, Clock3, Server, ShieldAlert } from 'lucide-react';
import { api } from '../api';
import { usePolling } from '../hooks/usePolling';
import { formatDateTime, formatRelative } from '../lib/format';

function StatCard({ label, value, detail, icon: Icon, tone = 'neutral', onClick }) {
  const content = (
    <>
      <div className="fleet-stat-top"><span>{label}</span><Icon size={16} aria-hidden="true" /></div>
      <div className={`fleet-stat-value ${tone}`}>{value}</div>
      <div className="fleet-stat-detail">{detail}</div>
    </>
  );
  return onClick
    ? <button className="fleet-stat-card is-clickable" onClick={onClick}>{content}</button>
    : <section className="fleet-stat-card">{content}</section>;
}

function hostAddress(node) {
  const address = node.collector_url?.replace(/^https?:\/\//, '').replace(/\/.*$/, '') || '';
  return address.endsWith(':20000') ? address.slice(0, -6) : address || '—';
}

function eventDescription(event) {
  if (event.event_type === 'alert') return event.alert_name || event.chart || 'Alert event';
  const contexts = event.contexts || [];
  return contexts.length ? contexts.join(', ') : 'Anomaly event';
}

export default function FleetOverviewTab({ fleet, nodes = [], query = '', onSelectNode, onChangeView, onShowHosts, onSelectInvestigation, onAddNode, canWrite, refreshMs }) {
  const events = usePolling(() => api.getEvents({ event_type: 'all', limit: 8 }), [], refreshMs, true);
  const investigations = usePolling(() => api.searchInvestigations({ limit: 5 }), [], refreshMs, true);
  const summary = fleet?.data?.summary;
  const counts = summary?.nodes;
  const attentionTotal = nodes.filter((node) => node.reachability !== 'reachable' || Number(node.active_alerts_count || 0) > 0).length;
  const alertingHosts = nodes.filter((node) => Number(node.active_alerts_count || 0) > 0).length;
  const filteredNodes = useMemo(() => {
    const needle = query.trim().toLowerCase();
    if (!needle) return nodes;
    return nodes.filter((node) => [node.hostname, node.collector_url, node.os_type].some((field) => String(field || '').toLowerCase().includes(needle)));
  }, [nodes, query]);
  const attention = useMemo(() => filteredNodes
    .filter((node) => node.reachability !== 'reachable' || Number(node.active_alerts_count || 0) > 0)
    .sort((a, b) => Number(b.active_alerts_count || 0) - Number(a.active_alerts_count || 0) || a.hostname.localeCompare(b.hostname)), [filteredNodes]);
  const latestEvents = events.data?.items || [];
  const recentInvestigations = investigations.data?.items || [];

  return (
    <div className="fleet-overview">
      <section className="fleet-page-heading">
        <div>
          <div className="fleet-eyebrow"><span>OPERATIONS</span><span className="fleet-heading-divider" /><span>LIVE FLEET STATE</span></div>
          <h1>Fleet overview</h1>
          <p>Current host reachability, active alerts, and recent activity from the connected PALANTIR services.</p>
        </div>
        <div className="fleet-heading-actions">
          <span className="fleet-updated-at"><Clock3 size={14} />{summary?.generated_at ? `Updated ${formatRelative(summary.generated_at)}` : 'Waiting for fleet summary'}</span>
          {canWrite && <button className="fleet-primary-button" onClick={onAddNode}><Server size={15} />Register host</button>}
        </div>
      </section>

      <section className="fleet-stat-grid" aria-label="Fleet summary">
        <StatCard label="Enabled hosts" value={counts ? counts.enabled : '—'} detail={counts ? `${counts.total} registered in total` : 'Waiting for fleet summary'} icon={Server} />
        <StatCard label="Reachable" value={counts ? counts.reachable : '—'} detail={counts ? 'Reporting within the reachability window' : 'Host status unavailable'} icon={CircleDot} tone="good" onClick={() => onShowHosts('online')} />
        <StatCard label="Needs attention" value={counts ? attentionTotal : '—'} detail={counts ? `${counts.stale} stale · ${counts.unreachable} unreachable · ${alertingHosts} with alerts` : 'Host status unavailable'} icon={AlertTriangle} tone={attentionTotal ? 'warning' : 'neutral'} onClick={() => onShowHosts('attention')} />
        <StatCard label="Active alerts" value={summary?.active_alerts ? summary.active_alerts.count : '—'} detail="Open warning and critical alerts" icon={ShieldAlert} tone={summary?.active_alerts?.count ? 'critical' : 'neutral'} onClick={() => onChangeView('events')} />
        <StatCard label="Anomalies · 24h" value={summary?.recent_anomalies ? summary.recent_anomalies.count : '—'} detail="Detected in the past 24 hours" icon={Activity} onClick={() => onChangeView('events')} />
      </section>

      <section className="fleet-overview-grid">
        <div className="fleet-panel fleet-attention-panel">
          <div className="fleet-panel-header">
            <div><div className="fleet-panel-kicker">HOST HEALTH</div><h2>Needs attention</h2></div>
            <button className="fleet-text-link" onClick={() => onShowHosts('all')}>All hosts <ArrowRight size={14} /></button>
          </div>
          {fleet?.loading && !fleet?.data ? <div className="fleet-panel-empty">Loading host status…</div> : attention.length ? (
            <div className="fleet-host-list">
              {attention.slice(0, 8).map((node) => {
                const reachability = node.reachability || 'unknown';
                const statusClass = reachability === 'stale' ? 'warning' : reachability === 'reachable' ? 'good' : 'critical';
                return (
                  <button className="fleet-host-row" key={node.id} onClick={() => onSelectNode(node.id)}>
                    <span className={`fleet-host-status ${statusClass}`}><CircleDot size={13} />{reachability}</span>
                    <span className="fleet-host-main"><strong>{node.hostname}</strong><small>{hostAddress(node)}</small></span>
                    <span className="fleet-host-last-seen">{node.last_seen_at ? formatRelative(node.last_seen_at) : 'No contact recorded'}</span>
                    {Number(node.active_alerts_count || 0) > 0 && <span className="fleet-alert-count"><AlertTriangle size={12} />{node.active_alerts_count}</span>}
                    <ArrowRight className="fleet-row-arrow" size={14} />
                  </button>
                );
              })}
            </div>
          ) : (
            <div className="fleet-panel-empty"><CircleDot size={17} />{query ? 'No hosts match this search.' : counts?.enabled === 0 ? 'No hosts are registered in this fleet.' : counts ? 'No hosts currently need attention.' : 'Host status is not available yet.'}</div>
          )}
          {attention.length > 8 && <button className="fleet-panel-footer-link" onClick={() => onShowHosts('attention')}>View all {attention.length} hosts needing attention <ArrowRight size={14} /></button>}
        </div>

        <div className="fleet-panel fleet-events-panel">
          <div className="fleet-panel-header">
            <div><div className="fleet-panel-kicker">LATEST FROM EVENT FEED</div><h2>Recent events</h2></div>
            <button className="fleet-text-link" onClick={() => onChangeView('events')}>Open feed <ArrowRight size={14} /></button>
          </div>
          {events.error && <div className="fleet-inline-error">{events.error}</div>}
          {events.loading && !events.data ? <div className="fleet-panel-empty">Loading events…</div> : latestEvents.length ? (
            <div className="fleet-event-list">
              {latestEvents.slice(0, 6).map((event) => {
                const isAlert = event.event_type === 'alert';
                const severity = String(event.severity || '').toLowerCase();
                return (
                  <button className="fleet-event-row" key={`${event.event_type}-${event.id}`} onClick={() => onChangeView('events')}>
                    <span className={`fleet-event-marker ${isAlert ? (severity === 'critical' ? 'critical' : 'warning') : 'anomaly'}`} />
                    <span className="fleet-event-copy"><span className="fleet-event-title">{eventDescription(event)}</span><span className="fleet-event-meta">{event.hostname || 'Fleet'} · {event.event_type || 'event'}</span></span>
                    <time title={formatDateTime(event.occurred_at)}>{formatRelative(event.occurred_at)}</time>
                  </button>
                );
              })}
            </div>
          ) : <div className="fleet-panel-empty">{events.data ? 'No events in the current feed.' : 'Event feed is unavailable.'}</div>}
        </div>

        <div className="fleet-panel fleet-investigations-panel">
          <div className="fleet-panel-header">
            <div><div className="fleet-panel-kicker">INVESTIGATION QUEUE</div><h2>Recent investigations</h2></div>
            <button className="fleet-text-link" onClick={() => onChangeView('investigations')}>View queue <ArrowRight size={14} /></button>
          </div>
          {investigations.error && <div className="fleet-inline-error">{investigations.error}</div>}
          {investigations.loading && !investigations.data ? <div className="fleet-panel-empty">Loading investigations…</div> : recentInvestigations.length ? (
            <div className="fleet-investigation-list">
              {recentInvestigations.slice(0, 5).map((item) => (
                <button className="fleet-investigation-row" key={item.id} onClick={() => onSelectInvestigation(item.id)}>
                  <span className={`fleet-investigation-status ${String(item.status || 'unknown').toLowerCase()}`}>{item.status || 'unknown'}</span>
                  <span className="fleet-investigation-copy"><strong>#{item.id} · {item.trigger_type || 'Investigation'}</strong><small>{item.node_hostname || nodes.find((node) => node.id === item.node_id)?.hostname || `Host ${item.node_id}`}</small></span>
                  <time>{formatRelative(item.completed_at || item.started_at || item.queued_at)}</time>
                </button>
              ))}
            </div>
          ) : <div className="fleet-panel-empty">{investigations.data ? 'No investigations have been recorded.' : 'Investigation queue is unavailable.'}</div>}
        </div>
      </section>
      <div className="fleet-overview-footnote">Live values are provided by PALANTIR’s fleet summary and event services. Host-specific metric charts are available from the Hosts screen.</div>
    </div>
  );
}
