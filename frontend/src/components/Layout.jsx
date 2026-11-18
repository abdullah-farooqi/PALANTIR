import { useEffect, useState } from 'react';
import {
  Activity, AlertTriangle, ChevronDown, Clock3, Gauge, LayoutDashboard,
  Logs, Menu, PanelLeftClose, PanelLeftOpen, RefreshCw, Search, Server,
  Settings2, ShieldCheck, Sparkles, X,
} from 'lucide-react';
import { UI_ROLE } from '../lib/role';
import { formatClock, formatRelative } from '../lib/format';

export const VIEWS = [
  { key: 'fleet-overview', label: 'Fleet Overview' },
  { key: 'fleet', label: 'Hosts' },
  { key: 'events', label: 'Alerts & Events' },
  { key: 'logs', label: 'Logs' },
  { key: 'investigations', label: 'Investigations' },
  { key: 'agent', label: 'Copilot Preview' },
  { key: 'settings', label: 'Settings' },
  { key: 'overview', label: 'Host Overview', sub: true },
  { key: 'inventory', label: 'Host Inventory', sub: true },
  { key: 'pcap', label: 'Network Evidence', sub: true },
];

export const REFRESH_OPTIONS = [
  { value: 5000, label: '5 sec' },
  { value: 10000, label: '10 sec' },
  { value: 30000, label: '30 sec' },
  { value: 0, label: 'Paused' },
];

const MAIN_NAV = [
  { key: 'fleet-overview', label: 'Fleet Overview', icon: LayoutDashboard },
  { key: 'fleet', label: 'Hosts', icon: Server },
  { key: 'events', label: 'Alerts & Events', icon: AlertTriangle },
  { key: 'logs', label: 'Logs', icon: Logs },
  { key: 'investigations', label: 'Investigations', icon: ShieldCheck },
  { key: 'pcap', label: 'Network Evidence', icon: Activity },
  { key: 'agent', label: 'Copilot Preview', icon: Sparkles, preview: true },
];

function getPage(view) {
  if (view === 'overview') return 'Host Overview';
  if (view === 'inventory') return 'Host Inventory';
  if (view === 'pcap') return 'Network Evidence';
  return VIEWS.find((item) => item.key === view)?.label || 'Fleet Overview';
}

function StatusDot({ tone = 'ok' }) {
  return <span className={`shell-status-dot ${tone}`} aria-hidden="true" />;
}

export function TopBar({
  view, setView, fleet, refreshMs, setRefreshMs, refreshing, onRefresh,
  query, setQuery, node, onOpenCommandPalette, children,
}) {
  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [now, setNow] = useState(Date.now());
  const summary = fleet?.data?.summary;
  const opsHealth = fleet?.data?.ops;
  const summaryComponents = [summary?.health?.api, summary?.health?.database, ...Object.values(summary?.health?.workers || {})].filter(Boolean);
  const operationsComponents = [opsHealth?.api, opsHealth?.database, opsHealth?.redis, opsHealth?.celery?.workers, opsHealth?.celery?.beat_dispatch, ...Object.values(opsHealth?.tasks || {})].filter(Boolean);
  const healthComponents = operationsComponents.length ? operationsComponents : summaryComponents;
  const unhealthyComponents = healthComponents.filter((component) => !['running', 'healthy'].includes(component.status)).length;
  const healthTone = !healthComponents.length ? 'unknown' : opsHealth?.status === 'degraded' || unhealthyComponents ? 'warn' : 'ok';
  const healthDetail = healthTone === 'unknown' ? 'health state unavailable' : healthTone === 'ok' ? 'dependency checks healthy' : `${unhealthyComponents || 1} health check(s) need attention`;
  const fleetCount = summary?.nodes?.enabled ?? fleet?.data?.nodes?.length ?? 0;
  const hostViews = ['overview', 'inventory'];
  const selectedHostView = hostViews.includes(view);
  const navActive = (key) => key === 'fleet'
    ? view === 'fleet' || selectedHostView
    : key === 'events'
      ? view === 'events'
      : view === key;

  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);

  function navigate(nextView) {
    setView(nextView);
    setMobileOpen(false);
  }

  return (
    <div className={`app-shell ${collapsed ? 'is-collapsed' : ''}`}>
      {mobileOpen && <button className="shell-mobile-scrim" aria-label="Close navigation" onClick={() => setMobileOpen(false)} />}
      <aside className={`shell-sidebar ${mobileOpen ? 'mobile-open' : ''}`} aria-label="Primary navigation">
        <div className="shell-brand-row">
          <button className="shell-brand" onClick={() => navigate('fleet-overview')} aria-label="PALANTIR fleet overview">
            <span className="shell-brand-mark">P</span>
            <span className="shell-brand-copy"><strong>PALANTIR</strong><small>FLEET OPERATIONS</small></span>
          </button>
          <button className="shell-icon-button shell-collapse-button" onClick={() => setCollapsed((value) => !value)} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'} title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
            {collapsed ? <PanelLeftOpen size={16} /> : <PanelLeftClose size={16} />}
          </button>
          <button className="shell-icon-button shell-close-mobile" onClick={() => setMobileOpen(false)} aria-label="Close navigation"><X size={17} /></button>
        </div>

        <div className="shell-nav-label">WORKSPACE</div>
        <nav className="shell-nav">
          {MAIN_NAV.map(({ key, label, icon: Icon, preview }) => (
            <button key={key} className={`shell-nav-item ${navActive(key) ? 'active' : ''}`} onClick={() => navigate(key)} aria-current={navActive(key) ? 'page' : undefined} title={collapsed ? label : undefined}>
              <Icon size={17} strokeWidth={1.8} />
              <span className="shell-nav-text">{label}</span>
              {preview && <span className="shell-preview-label">PREVIEW</span>}
            </button>
          ))}
        </nav>

        <div className="shell-sidebar-spacer" />
        <div className="shell-sidebar-status">
          <div className="shell-sidebar-status-head"><Activity size={14} /><span className="shell-nav-text">PIPELINE STATUS</span><StatusDot tone={healthTone} /></div>
          <div className="shell-nav-text shell-sidebar-status-copy">{fleetCount} registered {fleetCount === 1 ? 'host' : 'hosts'} · {healthDetail}</div>
        </div>
        <button className={`shell-nav-item shell-settings-item ${view === 'settings' ? 'active' : ''}`} onClick={() => navigate('settings')} aria-current={view === 'settings' ? 'page' : undefined} title={collapsed ? 'Settings' : undefined}>
          <Settings2 size={17} strokeWidth={1.8} /><span className="shell-nav-text">Settings</span>
        </button>
        <div className="shell-user-row">
          <span className="shell-user-avatar">{UI_ROLE === 'admin' ? 'A' : 'R'}</span>
          <span className="shell-user-copy"><strong>{UI_ROLE === 'admin' ? 'Administrator' : 'Read only'}</strong><small>{UI_ROLE.toUpperCase()} ACCESS</small></span>
        </div>
      </aside>

      <div className="shell-main-column">
        <header className="shell-topbar">
          <button className="shell-icon-button shell-mobile-menu" onClick={() => setMobileOpen(true)} aria-label="Open navigation"><Menu size={18} /></button>
          <div className="shell-breadcrumbs">
            <span>Operations</span><span className="shell-crumb-sep">/</span>
            {selectedHostView && node && <><button onClick={() => navigate('fleet')}>Hosts</button><span className="shell-crumb-sep">/</span><strong>{node.hostname}</strong><span className="shell-crumb-sep">/</span></>}
            <strong>{getPage(view)}</strong>
          </div>
          <div
            className="shell-global-search"
            onClick={(e) => {
              if (onOpenCommandPalette && e.target.tagName !== 'INPUT') {
                onOpenCommandPalette();
              }
            }}
          >
            <Search size={15} aria-hidden="true" />
            <input
              className="app-search-input"
              value={query || ''}
              onChange={(event) => setQuery(event.target.value)}
              onFocus={() => {
                if (onOpenCommandPalette) onOpenCommandPalette();
              }}
              placeholder="Search hosts or commands…"
              aria-label="Search hosts or press Ctrl+K for command palette"
            />
            <kbd
              onClick={(e) => {
                e.stopPropagation();
                onOpenCommandPalette && onOpenCommandPalette();
              }}
              style={{ cursor: 'pointer' }}
              title="Open command palette (Ctrl+K)"
            >
              Ctrl+K
            </kbd>
          </div>
          <div className="shell-topbar-right">
            <span className="shell-freshness" title={summary?.latest_metric_at ? `Latest metric collected ${summary.latest_metric_at}` : 'No metric has been collected yet'}>
              <StatusDot tone="unknown" />
              <span>{summary?.latest_metric_at ? `LATEST DATA ${formatRelative(summary.latest_metric_at)}` : 'NO DATA YET'}</span>
            </span>
            <span className={`shell-health-pill ${healthTone}`} title={healthDetail}>
              <StatusDot tone={healthTone} /><span>{healthTone === 'ok' ? 'SYSTEMS NORMAL' : healthTone === 'warn' ? 'CHECK PIPELINE' : 'HEALTH UNKNOWN'}</span>
            </span>
            <span className="shell-clock"><Clock3 size={14} /><span>{formatClock(now)}</span></span>
          </div>
        </header>
        <div className="shell-toolbar">
          <div className="shell-toolbar-context">
            {node && selectedHostView ? <><span className="shell-host-indicator"><Server size={14} />{node.hostname}</span><span className="shell-crumb-sep">·</span><span>{node.reachability || 'unknown'}</span></> : <><Gauge size={14} /><span>Fleet operations workspace</span></>}
          </div>
          <div className="shell-toolbar-actions">
            <label className="shell-refresh-select"><span>Refresh</span><select value={refreshMs} onChange={(event) => setRefreshMs(Number(event.target.value))} aria-label="Telemetry refresh interval">{REFRESH_OPTIONS.map((option) => <option key={option.value} value={option.value}>{option.label}</option>)}</select><ChevronDown size={13} /></label>
            <button className="shell-refresh-button" onClick={onRefresh} disabled={refreshing} title="Refresh fleet and current host data"><RefreshCw size={14} className={refreshing ? 'is-spinning' : ''} /><span>Refresh</span></button>
          </div>
        </div>
        <main className="term-main shell-content">{children}</main>
      </div>
    </div>
  );
}
