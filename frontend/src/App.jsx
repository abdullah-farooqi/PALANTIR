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
import ObservabilityTab from './components/ObservabilityTab';
import PcapTab from './components/PcapTab';
import AgentChatbotTab from './components/AgentChatbotTab';
import FleetGridTab from './components/FleetGridTab';

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
  const [view, setView] = useState(() => (VIEWS.some((v) => v.key === read('palantir.view')) ? read('palantir.view') : 'observability'));
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
  const [pendingRemoveNode, setPendingRemoveNode] = useState(null);
  const [toast, setToast] = useState(null);
  const toastTimer = useRef(null);
  const [prevView, setPrevView] = useState('observability');
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
    changeView('fleet');
  }, [changeView]);
  const goBackFromSettings = useCallback(() => {
    changeView(prevView || 'fleet');
  }, [changeView, prevView]);
  const toggleSettings = useCallback(() => {
    if (view === 'settings') {
      changeView(prevView || 'fleet');
    } else {
      changeView('settings');
    }
  }, [view, changeView, prevView]);
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
    setPendingRemoveNode(toRemove);
  }

  // ---- keyboard (Forensic Instrument hotkeys) -----------------------------------
  useEffect(() => {
    function onKey(e) {
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const tag = (e.target && e.target.tagName) || '';
      if (['INPUT', 'TEXTAREA', 'SELECT'].includes(tag)) {
        if (e.key === 'Escape') e.target.blur();
        return;
      }
      if (showAdd || pendingRemoveNode) return;
      if (e.key === '1') changeView('observability');
      else if (e.key === '2') changeView('pcap');
      else if (e.key === '3') changeView('agent');
      else if (e.key === '4') changeView('fleet');
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
        const el = document.querySelector('input.in') || document.getElementById('global-instrument-search');
        if (el) { e.preventDefault(); el.focus(); }
      } else if (view === 'inventory') {
        const s = INVENTORY_SECTIONS.find((x) => x.hotkey === e.key);
        if (s) setSection(s.value);
      }
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [nodes, selectedId, range, view, showAdd, pendingRemoveNode, refreshAll, changeView, setRange]);

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
  } else if (nodes.length === 0) {
    body = (
      <div style={{ maxWidth: 860, margin: '30px auto', padding: '0 16px' }}>
        <div
          className="box hot"
          style={{
            background: '#070c08',
            borderColor: '#193822',
            borderRadius: '14px',
            padding: '28px 24px',
            boxShadow: '0 0 35px rgba(20, 60, 30, 0.35)',
            marginBottom: '24px'
          }}
        >
          <div className="box-title" style={{ fontSize: '14px', marginBottom: '16px' }}>
            <span className="t-edge">┐</span>
            <span className="t-chip">
              <span className="t-name" style={{ fontSize: '15px', color: '#39e569' }}>
                Welcome to PALANTIR — No Hosts Enrolled
              </span>
            </span>
            <span className="t-edge">┌</span>
            <span className="t-line" />
          </div>

          <div style={{ color: '#a3c4aa', fontSize: '14px', lineHeight: '1.6', marginBottom: '18px' }}>
            There are currently no machines registered in your cluster. You can register this master host or any remote server, VM, or cloud instance.
          </div>

          <div
            style={{
              background: '#040705',
              border: '1px solid #16301d',
              borderRadius: '8px',
              padding: '14px 18px',
              fontFamily: 'JetBrains Mono, monospace',
              fontSize: '13px',
              color: '#728c78',
              lineHeight: '1.7'
            }}
          >
            <div style={{ color: '#39e569', fontWeight: 600, marginBottom: '6px' }}>
              How to setup and enroll target hosts:
            </div>
            <div>
              1. On any physical host, VM, or local system, run:
            </div>
            <div style={{ color: '#22d3ee', margin: '4px 0 8px 12px' }}>
              sudo bash scripts/Automatic-Host-Setup.sh
            </div>
            <div>
              2. For VirtualBox / VMware / NAT VMs, configure port forwarding with:
            </div>
            <div style={{ color: '#22d3ee', margin: '4px 0 8px 12px' }}>
              sudo bash scripts/Automatic-VM-Setup-For-NAT.sh
            </div>
            <div>
              3. Once the collector is active on port 20000, add the node below.
            </div>
          </div>
        </div>

        {CAN_WRITE && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 320px))', gap: '20px' }}>
            <div
              className="cyber-node-card add-node-card"
              onClick={() => setShowAdd(true)}
              style={{
                cursor: 'pointer',
                borderRadius: '14px',
                minHeight: '220px',
                border: '1.5px dashed #275635',
                background: 'rgba(8, 15, 10, 0.6)'
              }}
            >
              <div className="add-node-content">
                <div className="add-node-icon" style={{ fontSize: '32px', color: '#39e569', fontWeight: 700 }}>+</div>
                <div className="add-node-title" style={{ fontSize: '16px', fontWeight: 700, color: '#39e569' }}>
                  Register First Host
                </div>
                <div style={{ fontSize: '12px', color: '#728c78', maxWidth: '200px', marginTop: '4px' }}>
                  Click to add a host IP or press hotkey “a”
                </div>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  } else if (view === 'observability') {
    body = (
      <ObservabilityTab
        nodes={nodes}
        searchFilter={query}
        onSelectNode={selectNodeDetail}
        onChangeView={changeView}
      />
    );
  } else if (view === 'pcap') {
    body = <PcapTab onToast={notify} />;
  } else if (view === 'agent') {
    body = <AgentChatbotTab onToast={notify} />;
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
  } else if (!node) {
    body = (
      <div style={{ textAlign: 'center', padding: '48px 16px', background: '#14171B', border: '1px dashed #262B32', borderRadius: '6px', maxWidth: 640, margin: '40px auto' }}>
        <p style={{ color: '#8B93A0', fontSize: '13px', marginBottom: '16px' }}>
          No target host node selected for deep telemetry investigation.
        </p>
        <button
          className="btn primary"
          onClick={() => changeView('fleet')}
          style={{ background: '#C6FF00', color: '#0A0B0D', fontWeight: 700, padding: '7px 20px', borderRadius: '4px', fontSize: '12px' }}
        >
          Select from Hosts Grid
        </button>
      </div>
    );
  } else if (view === 'overview') {
    body = <OverviewTab node={node} state={nodeData} range={range} setRange={setRange} onBack={goBack} onChangeView={changeView} onToast={notify} onRefresh={nodeData.refresh} killedPids={killedPids} onKilledPids={handleKilledPids} />;
  } else if (view === 'inventory') {
    body = <InventoryTab node={node} state={nodeData} section={section} setSection={setSection} onBack={goBack} onChangeView={changeView} onToast={notify} onRefresh={nodeData.refresh} onKilledPids={handleKilledPids} />;
  } else if (view === 'events') {
    body = <AlertsTab node={node} state={nodeData} scope={scope} setScope={setScope} onInvestigate={onInvestigate} refreshMs={refreshMs} onBack={goBack} onChangeView={changeView} />;
  } else if (view === 'logs') {
    body = <LogsTab node={node} scope={scope} setScope={setScope} refreshMs={refreshMs} onBack={goBack} onChangeView={changeView} />;
  } else {
    body = <InvestigationsTab node={node} scope={scope} setScope={setScope} refreshMs={refreshMs} focusId={focusInv} onToast={notify} onBack={goBack} onChangeView={changeView} fleet={fleet} />;
  }

  return (
    <div className="term">
      <TopBar
        view={view}
        setView={changeView}
        onToggleSettings={toggleSettings}
        fleet={fleet}
        refreshMs={refreshMs}
        setRefreshMs={setRefreshMs}
        refreshing={fleet.refreshing || nodeData.refreshing}
        onRefresh={refreshAll}
        query={query}
        setQuery={setQuery}
      />
      <main className="term-main">
        {nodeData.error && node && nodeData.data && view !== 'logs' && view !== 'investigations' && view !== 'fleet' && view !== 'observability' && view !== 'pcap' && view !== 'agent' && <ErrorLine warn>{nodeData.error}</ErrorLine>}
        {nodeData.error && node && !nodeData.data && view !== 'logs' && view !== 'investigations' && view !== 'fleet' && view !== 'observability' && view !== 'pcap' && view !== 'agent' && <ErrorLine>{nodeData.error}</ErrorLine>}
        {body}
      </main>
      {showAdd && <AddNodeModal onClose={() => setShowAdd(false)} onCreated={(n) => { setShowAdd(false); setSelectedId(n.id); fleet.refresh(); notify(`registered ${n.hostname}`); }} />}
      
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
