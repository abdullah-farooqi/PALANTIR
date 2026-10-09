import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { api } from './api';
import { useFleet } from './hooks/useFleet';
import { useNodeData } from './hooks/useNodeData';
import { RANGES } from './lib/metrics';
import { CAN_WRITE } from './lib/role';
import ErrorBoundary from './components/ErrorBoundary';
import { NodeBar, REFRESH_OPTIONS, TopBar, VIEWS } from './components/Layout';
import OverviewTab from './components/OverviewTab';
import InventoryTab, { INVENTORY_SECTIONS } from './components/InventoryTab';
import AlertsTab from './components/AlertsTab';
import LogsTab from './components/LogsTab';
import InvestigationsTab from './components/InvestigationsTab';
import SettingsTab from './components/SettingsTab';
import AddNodeModal from './components/AddNodeModal';
import { Empty, ErrorLine, Toast } from './components/ui';

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

import FleetGridTab from './components/FleetGridTab';

function Dashboard() {
  const [view, setView] = useState(() => (VIEWS.some((v) => v.key === read('palantir.view')) ? read('palantir.view') : 'fleet'));
  const [selectedId, setSelectedId] = useState(() => Number(read('palantir.node', 0)) || null);
  const [range, setRangeState] = useState(() => RANGES.find((r) => r.key === read('palantir.range')) || RANGES[0]);
  const [refreshMs, setRefreshMsState] = useState(() => {
    const v = Number(read('palantir.refresh', 10000));
    return REFRESH_OPTIONS.some((o) => o.value === v) ? v : 10000;
  });
  const [query, setQuery] = useState('');
  const [section, setSection] = useState('services');
  const [scope, setScope] = useState('node'); // events / logs / investigations: this node or whole fleet
  const [focusInv, setFocusInv] = useState(null);
  const [showAdd, setShowAdd] = useState(false);
  const [toast, setToast] = useState(null);
  const toastTimer = useRef(null);

  const setRange = useCallback((r) => { setRangeState(r); write('palantir.range', r.key); }, []);
  const setRefreshMs = useCallback((v) => { setRefreshMsState(v); write('palantir.refresh', v); }, []);
  const changeView = useCallback((v) => { setView(v); write('palantir.view', v); }, []);
  const notify = useCallback((text, error = false) => {
    setToast({ text, error });
    clearTimeout(toastTimer.current);
    toastTimer.current = setTimeout(() => setToast(null), 4500);
  }, []);

  // ---- data -----------------------------------------------------------------
  const fleet = useFleet(refreshMs || 15000);
  const nodes = useMemo(() => (fleet.data ? fleet.data.nodes : []), [fleet.data]);

  // Keep the selection valid: stored node if it still exists, otherwise the first node.
  useEffect(() => {
    if (nodes.length === 0) return;
    if (!nodes.some((n) => n.id === selectedId)) setSelectedId(nodes[0].id);
  }, [nodes, selectedId]);
  useEffect(() => { if (selectedId) write('palantir.node', selectedId); }, [selectedId]);

  const node = nodes.find((n) => n.id === selectedId) || null;
  const nodeData = useNodeData(node ? node.id : null, range, refreshMs, view, section);

  const refreshAll = useCallback(() => { fleet.refresh(); nodeData.refresh(); }, [fleet, nodeData]);

  const selectNodeDetail = useCallback((nodeId) => {
    setSelectedId(nodeId);
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
    if (!window.confirm(`Deactivate ${toRemove.hostname}? History is kept; polling stops.`)) return;
    try {
      await api.deleteNode(toRemove.id);
      notify(`${toRemove.hostname} deactivated`);
      fleet.refresh();
    } catch (err) {
      notify(err.message, true);
    }
  }

  // ---- keyboard (btop-style) ----------------------------------------------------
  useEffect(() => {
    function onKey(e) {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const tag = (e.target && e.target.tagName) || '';
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(tag)) {
        if (e.key === 'Escape') e.target.blur();
        return;
      }
      if (showAdd) return;
      const idx = nodes.findIndex((n) => n.id === selectedId);
      if (e.key >= '1' && e.key <= String(VIEWS.length)) changeView(VIEWS[Number(e.key) - 1].key);
      else if (e.key === '[' && nodes.length) setSelectedId(nodes[(idx - 1 + nodes.length) % nodes.length].id);
      else if (e.key === ']' && nodes.length) setSelectedId(nodes[(idx + 1) % nodes.length].id);
      else if (e.key === 'r') refreshAll();
      else if (e.key === 't') setRange(RANGES[(RANGES.findIndex((r) => r.key === range.key) + 1) % RANGES.length]);
      else if (e.key === 'a' && CAN_WRITE) { e.preventDefault(); setShowAdd(true); }
      else if (e.key === '/') {
        const el = document.querySelector('input.in');
        if (el) { e.preventDefault(); el.focus(); }
      } else if (view === 'inventory') {
        const s = INVENTORY_SECTIONS.find((x) => x.hotkey === e.key);
        if (s) setSection(s.value);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [nodes, selectedId, range, view, showAdd, refreshAll, changeView, setRange]);

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
  } else if (nodes.length === 0) {
    body = (
      <Empty>
        No nodes registered. The central stack registers <b>local-node</b> on boot; remote hosts enrol with <span className="tone-fg">scripts/setup-agent.sh</span>.
        {CAN_WRITE ? ' Press “a” to add one by hand.' : ''}
      </Empty>
    );
  } else if (view === 'fleet') {
    body = (
      <FleetGridTab
        nodes={nodes}
        query={query}
        setQuery={setQuery}
        onSelectNode={selectNodeDetail}
        onAddNode={() => setShowAdd(true)}
        onRemoveNode={removeNode}
        CAN_WRITE={CAN_WRITE}
      />
    );
  } else if (view === 'settings') {
    body = <SettingsTab node={node} data={nodeData.data} refreshMs={refreshMs} setRefreshMs={setRefreshMs} onRefresh={refreshAll} refreshing={fleet.refreshing || nodeData.refreshing} onBack={() => changeView('fleet')} />;
  } else if (!node) {
    body = <Empty>Select a node.</Empty>;
  } else if (view === 'overview') {
    body = <OverviewTab node={node} state={nodeData} range={range} setRange={setRange} onBack={() => changeView('fleet')} />;
  } else if (view === 'inventory') {
    body = <InventoryTab node={node} state={nodeData} section={section} setSection={setSection} />;
  } else if (view === 'events') {
    body = <AlertsTab node={node} state={nodeData} scope={scope} setScope={setScope} onInvestigate={onInvestigate} refreshMs={refreshMs} />;
  } else if (view === 'logs') {
    body = <LogsTab node={node} scope={scope} setScope={setScope} refreshMs={refreshMs} />;
  } else {
    body = <InvestigationsTab node={node} scope={scope} setScope={setScope} refreshMs={refreshMs} focusId={focusInv} onToast={notify} />;
  }

  return (
    <div className="term">
      <TopBar
        view={view}
        setView={changeView}
        fleet={fleet}
        refreshMs={refreshMs}
        setRefreshMs={setRefreshMs}
        refreshing={fleet.refreshing || nodeData.refreshing}
        onRefresh={refreshAll}
        query={query}
        setQuery={setQuery}
      />
      <main className="term-main">
        {nodeData.error && node && nodeData.data && view !== 'logs' && view !== 'investigations' && view !== 'fleet' && <ErrorLine warn>{nodeData.error}</ErrorLine>}
        {nodeData.error && node && !nodeData.data && view !== 'logs' && view !== 'investigations' && view !== 'fleet' && <ErrorLine>{nodeData.error}</ErrorLine>}
        {body}
      </main>
      {showAdd && <AddNodeModal onClose={() => setShowAdd(false)} onCreated={(n) => { setShowAdd(false); setSelectedId(n.id); fleet.refresh(); notify(`registered ${n.hostname}`); }} />}
      <Toast toast={toast} />
    </div>
  );
}

export default function App() {
  return (
    <ErrorBoundary>
      <Dashboard />
    </ErrorBoundary>
  );
}
