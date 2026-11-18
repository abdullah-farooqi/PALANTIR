import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from './api';
import { useFleet } from './hooks/useFleet';
import { useNodeData } from './hooks/useNodeData';
import { RANGES } from './lib/metrics';
import { CAN_WRITE } from './lib/role';
import ErrorBoundary from './components/ErrorBoundary';
import { REFRESH_OPTIONS, TopBar, VIEWS } from './components/Layout';
import OverviewTab from './components/OverviewTab';
import InventoryTab, { INVENTORY_SECTIONS } from './components/InventoryTab';
import AlertsTab from './components/AlertsTab';
import LogsTab from './components/LogsTab';
import InvestigationsTab from './components/InvestigationsTab';
import SettingsTab from './components/SettingsTab';
import AddNodeModal from './components/AddNodeModal';
import { Empty, ErrorLine, Toast } from './components/ui';
import PcapTab from './components/PcapTab';
import AgentChatbotTab from './components/AgentChatbotTab';
import FleetGridTab from './components/FleetGridTab';
import FleetOverviewTab from './components/FleetOverviewTab';
import CommandPalette from './components/CommandPalette';
import PivotForensicDrawer from './components/PivotForensicDrawer';

const read = (k, d) => {
  try {
    const v = window.localStorage.getItem(k);
    return v === null ? d : v;
  } catch (err) {
    return d;
  }
};
const write = (k, v) => {
  try {
    window.localStorage.setItem(k, String(v));
  } catch (err) {
    // storage unavailable — ignore
  }
};

function Dashboard() {
  const [view, setView] = useState(() => (VIEWS.some((v) => v.key === read('palantir.view')) ? read('palantir.view') : 'fleet-overview'));
  const [selectedId, setSelectedId] = useState(() => Number(read('palantir.node', 0)) || null);
  const [range, setRangeState] = useState(() => RANGES.find((r) => r.key === read('palantir.range')) || RANGES[0]);
  const [refreshMs, setRefreshMsState] = useState(() => {
    const v = Number(read('palantir.refresh', 10000));
    return REFRESH_OPTIONS.some((o) => o.value === v) ? v : 10000;
  });
  const [query, setQuery] = useState('');
  const [hostFilter, setHostFilter] = useState('all');
  const [section, setSection] = useState('services');
  const [scope, setScope] = useState(() => ['overview', 'inventory'].includes(read('palantir.view')) ? 'node' : 'fleet');
  const [focusInv, setFocusInv] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [pendingRemoveNode, setPendingRemoveNode] = useState(null);
  const [toast, setToast] = useState(null);
  const toastTimer = useRef(null);
  const [prevView, setPrevView] = useState('fleet-overview');
  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);
  const [pivotDrawer, setPivotDrawer] = useState({ isOpen: false, query: '', type: '' });
  const [killedPids, setKilledPids] = useState(() => new Set());
  const handleKilledPids = useCallback((pids) => {
    if (!pids) return;
    const list = Array.isArray(pids) ? pids : [pids];
    const nums = list.map(Number).filter((n) => n > 1);
    if (nums.length > 0) {
      setKilledPids((prev) => new Set([...prev, ...nums]));
    }
  }, []);

  const setRange = useCallback((r) => { setRangeState(r); write('palantir.range', r.key); }, []);
  const setRefreshMs = useCallback((v) => { setRefreshMsState(v); write('palantir.refresh', v); }, []);
  const changeView = useCallback((v) => {
    setView((current) => {
      if (current !== 'settings' && v === 'settings') {
        setPrevView(current);
      }
      return v;
    });
    write('palantir.view', v);
  }, []);
  const goBack = useCallback(() => {
    setScope('fleet');
    changeView('fleet');
  }, [changeView]);
  const goBackFromSettings = useCallback(() => {
    changeView(prevView || 'fleet');
  }, [changeView, prevView]);
  const navigateShell = useCallback((nextView) => {
    if (['events', 'logs', 'investigations', 'pcap'].includes(nextView)) setScope('fleet');
    if (nextView === 'fleet') setHostFilter('all');
    setFocusInv(null);
    changeView(nextView);
  }, [changeView]);
  const showHosts = useCallback((filter = 'all') => {
    setHostFilter(filter);
    changeView('fleet');
  }, [changeView]);
  const openInvestigation = useCallback((id) => {
    setScope('fleet');
    setFocusInv(id);
    changeView('investigations');
  }, [changeView]);
  const notify = useCallback((text, error = false) => {
    setToast({ text, error });
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 4500);
  }, []);

  const openPivot = useCallback((q, type) => {
    if (!q) return;
    setPivotDrawer({ isOpen: true, query: String(q), type: type || 'IPv4' });
  }, []);

  const closePivot = useCallback(() => {
    setPivotDrawer((prev) => ({ ...prev, isOpen: false }));
  }, []);

  const handleFilterAllViews = useCallback((qStr) => {
    setQuery(qStr);
    setHostFilter('all');
    navigateShell('fleet');
    closePivot();
  }, [navigateShell, closePivot]);

  // ---- data -----------------------------------------------------------------
  const fleet = useFleet(refreshMs);
  const nodes = useMemo(() => (fleet.data ? fleet.data.nodes : []), [fleet.data]);

  // Keep the selection valid: stored node if it still exists, otherwise the first node.
  useEffect(() => {
    if (nodes.length === 0) return;
    if (!nodes.some((n) => n.id === selectedId)) setSelectedId(nodes[0].id);
  }, [nodes, selectedId]);
  useEffect(() => { if (selectedId) write('palantir.node', selectedId); }, [selectedId]);

  const node = nodes.find((n) => n.id === selectedId) || null;
  const nodeDataEnabled = ['overview', 'inventory', 'settings'].includes(view) || (view === 'events' && scope === 'node');
  const nodeData = useNodeData(nodeDataEnabled && node ? node.id : null, range, refreshMs, view, section);

  const refreshAll = useCallback(() => {
    fleet.refresh();
    if (nodeDataEnabled && node) nodeData.refresh();
  }, [fleet, nodeData, nodeDataEnabled, node]);

  const selectNodeDetail = useCallback((nodeId) => {
    setSelectedId(nodeId);
    setScope('node');
    changeView('overview');
  }, [changeView]);

  // ---- actions ----------------------------------------------------------------
  const onInvestigate = useCallback(async (type, id, existing, nodeId) => {
    if (existing) {
      setFocusInv(existing);
      changeView('investigations');
      return;
    }
    const target = nodeId || (node && node.id);
    if (!target) return;
    try {
      const inv = await api.triggerInvestigation(target, type || 'manual', id || null);
      notify(`investigation #${inv.id} queued`);
      setFocusInv(inv.id);
      changeView('investigations');
    } catch (err) {
      notify(err.message, true);
    }
  }, [node, notify, changeView]);

  async function removeNode(targetNode) {
    const toRemove = targetNode || node;
    if (!toRemove) return;
    setPendingRemoveNode(toRemove);
  }

  // ---- keyboard (Forensic Instrument hotkeys) -----------------------------------
  useEffect(() => {
    function onKey(e) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
        return;
      }
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const tag = (e.target && e.target.tagName) || '';
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(tag)) {
        if (e.key === 'Escape') e.target.blur();
        return;
      }
      if (showAdd || pendingRemoveNode || commandPaletteOpen || pivotDrawer.isOpen) return;
      if (e.key === '1') navigateShell('fleet-overview');
      else if (e.key === '2') navigateShell('fleet');
      else if (e.key === '3') navigateShell('events');
      else if (e.key === '4') navigateShell('logs');
      else if (e.key === '[' && nodes.length) {
        const idx = nodes.findIndex((n) => n.id === selectedId);
        setSelectedId(nodes[(idx - 1 + nodes.length) % nodes.length].id);
      }
      else if (e.key === ']' && nodes.length) {
        const idx = nodes.findIndex((n) => n.id === selectedId);
        setSelectedId(nodes[(idx + 1) % nodes.length].id);
      }
      else if (e.key === 'r') refreshAll();
      else if (e.key === 't') setRange(RANGES[(RANGES.findIndex((r) => r.key === range.key) + 1) % RANGES.length]);
      else if (e.key === 'a' && CAN_WRITE) { e.preventDefault(); setShowAdd(true); }
      else if (e.key === '/') {
        const el = document.querySelector('input.app-search-input');
        if (el) { e.preventDefault(); el.focus(); }
      } else if (view === 'inventory') {
        const s = INVENTORY_SECTIONS.find((x) => x.hotkey === e.key);
        if (s) setSection(s.value);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [nodes, selectedId, range, view, showAdd, pendingRemoveNode, commandPaletteOpen, pivotDrawer.isOpen, refreshAll, navigateShell, setRange]);

  // ---- render -------------------------------------------------------------------
  let body;
  if (fleet.loading && !fleet.data) {
    body = <Empty><span className="spinner" /> connecting to the PALANTIR API…</Empty>;
  } else if (!fleet.data) {
    body = (
      <div style={{ maxWidth: 760, marginTop: 20 }}>
        <ErrorLine>{fleet.error || 'Cannot load nodes'}</ErrorLine>
        <div className="tone-dim" style={{ marginTop: 8 }}>
          Checklist: <br />
          1. backend up: <span className="tone-fg">docker compose ps</span> (backend on 127.0.0.1:8000) <br />
          2. tokens: PALANTIR_API_READ_TOKEN / PALANTIR_API_ADMIN_TOKEN set in the repo <span className="tone-fg">.env</span> <br />
          3. restart the UI after editing .env: <span className="tone-fg">cd frontend && npm run dev</span>
        </div>
      </div>
    );
  } else if (view === 'settings') {
    body = (
      <SettingsTab
        node={node}
        data={nodeData.data}
        fleet={fleet}
        refreshMs={refreshMs}
        setRefreshMs={setRefreshMs}
        onRefresh={refreshAll}
        refreshing={fleet.refreshing || nodeData.refreshing}
        onBack={goBackFromSettings}
        onToast={notify}
      />
    );
  } else if (view === 'fleet-overview') {
    body = <FleetOverviewTab fleet={fleet} nodes={nodes} query={query} onSelectNode={selectNodeDetail} onChangeView={changeView} onShowHosts={showHosts} onSelectInvestigation={openInvestigation} onAddNode={() => setShowAdd(true)} canWrite={CAN_WRITE} refreshMs={refreshMs} onPivot={openPivot} />;
  } else if (view === 'pcap') {
    body = <PcapTab onOpenInvestigations={() => navigateShell('investigations')} refreshMs={refreshMs} onPivot={openPivot} />;
  } else if (view === 'agent') {
    body = <AgentChatbotTab onToast={notify} />;
  } else if (view === 'fleet') {
    body = (
      <FleetGridTab
        nodes={nodes}
        query={query}
        setQuery={setQuery}
        initialFilter={hostFilter}
        refreshMs={refreshMs}
        onSelectNode={selectNodeDetail}
        onAddNode={() => setShowAdd(true)}
        onRemoveNode={removeNode}
        CAN_WRITE={CAN_WRITE}
        onPivot={openPivot}
      />
    );
  } else if (view === 'events') {
    body = <AlertsTab node={node} state={nodeData} scope={scope} setScope={setScope} onInvestigate={onInvestigate} refreshMs={refreshMs} onBack={goBack} onChangeView={changeView} onPivot={openPivot} onToast={notify} />;
  } else if (view === 'logs') {
    body = <LogsTab node={node} scope={scope} setScope={setScope} refreshMs={refreshMs} onBack={goBack} onChangeView={changeView} onPivot={openPivot} />;
  } else if (view === 'investigations') {
    body = <InvestigationsTab node={node} scope={scope} setScope={setScope} refreshMs={refreshMs} focusId={focusInv} onToast={notify} onBack={goBack} onChangeView={changeView} fleet={fleet} onPivot={openPivot} />;
  } else if (!node) {
    body = (
      <div style={{ textAlign: 'center', padding: '48px 16px', background: '#14171B', border: '1px dashed #262B32', borderRadius: '6px', maxWidth: 640, margin: '40px auto' }}>
        <p style={{ color: '#8B93A0', fontSize: '13px', marginBottom: '16px' }}>
          No target host node selected for deep telemetry investigation.
        </p>
        <button
          className="btn primary"
          onClick={() => navigateShell('fleet')}
          style={{ background: '#C6FF00', color: '#0A0B0D', fontWeight: 700, padding: '7px 20px', borderRadius: '4px', fontSize: '12px' }}
        >
          Select from Hosts Grid
        </button>
      </div>
    );
  } else if (view === 'overview') {
    body = <OverviewTab node={node} state={nodeData} range={range} setRange={setRange} onBack={goBack} onChangeView={changeView} onToast={notify} onRefresh={nodeData.refresh} killedPids={killedPids} onKilledPids={handleKilledPids} onPivot={openPivot} />;
  } else if (view === 'inventory') {
    body = <InventoryTab node={node} state={nodeData} section={section} setSection={setSection} onBack={goBack} onChangeView={changeView} onToast={notify} onRefresh={nodeData.refresh} onKilledPids={handleKilledPids} onPivot={openPivot} />;
  } else {
    body = <OverviewTab node={node} state={nodeData} range={range} setRange={setRange} onBack={goBack} onChangeView={changeView} onToast={notify} onRefresh={nodeData.refresh} killedPids={killedPids} onKilledPids={handleKilledPids} onPivot={openPivot} />;
  }

  return (
    <>
      <TopBar
        view={view}
        setView={navigateShell}
        fleet={fleet}
        refreshMs={refreshMs}
        setRefreshMs={setRefreshMs}
        refreshing={fleet.refreshing || nodeData.refreshing}
        onRefresh={refreshAll}
        node={node}
        query={query}
        setQuery={setQuery}
        onOpenCommandPalette={() => setCommandPaletteOpen(true)}
      >
        {nodeData.error && node && nodeData.data && ['overview', 'inventory', 'events'].includes(view) && <ErrorLine warn>{nodeData.error}</ErrorLine>}
        {nodeData.error && node && !nodeData.data && ['overview', 'inventory', 'events'].includes(view) && <ErrorLine>{nodeData.error}</ErrorLine>}
        {body}
      </TopBar>
      {showAdd && <AddNodeModal onClose={() => setShowAdd(false)} onCreated={(n) => { setShowAdd(false); setSelectedId(n.id); fleet.refresh(); notify(`registered ${n.hostname}`); }} />}
      
      <CommandPalette
        isOpen={commandPaletteOpen}
        onClose={() => setCommandPaletteOpen(false)}
        nodes={nodes}
        onSelectNode={(nodeId) => selectNodeDetail(nodeId)}
        onChangeView={(v) => navigateShell(v)}
        onAddNode={() => setShowAdd(true)}
        onTriggerIngest={async () => {
          try {
            const result = await api.triggerIngest();
            notify(result.task_id ? `Telemetry ingest queued (${result.task_id})` : 'Telemetry ingest queued');
            fleet.refresh();
          } catch (err) {
            notify(err.message, true);
          }
        }}
        onExportAlerts={async () => {
          try {
            const res = await api.exportEvents('stix');
            const blob = new Blob([JSON.stringify(res, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `palantir-alerts-stix-${new Date().toISOString().slice(0, 10)}.json`;
            a.click();
            URL.revokeObjectURL(url);
            notify('STIX 2.1 alert bundle downloaded');
          } catch (err) {
            notify(err.message, true);
          }
        }}
      />

      <PivotForensicDrawer
        isOpen={pivotDrawer.isOpen}
        onClose={closePivot}
        initialQuery={pivotDrawer.query}
        initialType={pivotDrawer.type}
        onFilterAllViews={handleFilterAllViews}
        onToast={notify}
      />

      {/* Themed Safe Deactivation Confirmation Modal */}
      {pendingRemoveNode && (
        <div
          className="modal-back"
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(10, 11, 13, 0.85)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
          }}
          onMouseDown={(e) => {
            if (e.target === e.currentTarget) setPendingRemoveNode(null);
          }}
        >
          <div
            className="box modal hot"
            role="dialog"
            aria-modal="true"
            aria-labelledby="deactivate-dialog-title"
            style={{
              maxWidth: 440,
              width: '90%',
              padding: '22px 20px',
              background: '#14171B',
              border: '1px solid #E5484D',
              borderRadius: 6,
              boxShadow: '0 10px 30px rgba(0,0,0,0.8)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <span style={{ color: '#E5484D', fontSize: 18 }} aria-hidden="true">⚠</span>
              <h3 id="deactivate-dialog-title" style={{ margin: 0, fontSize: 15, fontWeight: 700, color: '#FFA4A7', fontFamily: 'Space Grotesk, sans-serif' }}>
                DEACTIVATE HOST NODE
              </h3>
            </div>

            <p style={{ margin: '0 0 18px', fontSize: 13, color: '#E8EAED', lineHeight: 1.5, fontFamily: 'Space Grotesk, sans-serif' }}>
              Deactivate host <b style={{ color: '#C6FF00', fontFamily: 'JetBrains Mono, monospace' }}>{pendingRemoveNode.hostname}</b>? Historical snapshots will be retained, but active polling and alert evaluation will stop.
            </p>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 10 }}>
              <button
                type="button"
                className="btn"
                onClick={() => setPendingRemoveNode(null)}
                style={{
                  background: 'transparent',
                  border: '1px solid #262B32',
                  color: '#8B93A0',
                  padding: '6px 14px',
                  borderRadius: 4,
                  cursor: 'pointer',
                  fontWeight: 600,
                  fontSize: 12,
                }}
              >
                Cancel
              </button>
              <button
                type="button"
                className="btn"
                onClick={async () => {
                  const toRemove = pendingRemoveNode;
                  setPendingRemoveNode(null);
                  try {
                    await api.deleteNode(toRemove.id);
                    notify(`${toRemove.hostname} deactivated`);
                    fleet.refresh();
                  } catch (err) {
                    notify(err.message, true);
                  }
                }}
                style={{
                  background: '#E5484D',
                  border: 'none',
                  color: '#0A0B0D',
                  padding: '6px 16px',
                  borderRadius: 4,
                  cursor: 'pointer',
                  fontWeight: 700,
                  fontSize: 12,
                }}
              >
                Confirm Deactivation
              </button>
            </div>
          </div>
        </div>
      )}

      <Toast toast={toast} />
    </>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <Dashboard />
    </ErrorBoundary>
  );
}
