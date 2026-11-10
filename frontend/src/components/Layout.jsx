import React, { useEffect, useState, memo, useCallback } from 'react';
import { Dot, Spinner } from './ui';
import { CAN_WRITE, UI_ROLE } from '../lib/role';
import { formatClock, formatRelative } from '../lib/format';
import { statusTone } from '../lib/events';

export const VIEWS = [
  { key: 'observability', label: '1. OBSERVABILITY', hotkey: '1' },
  { key: 'pcap', label: '2. PCAP FORENSICS', hotkey: '2' },
  { key: 'agent', label: '3. AGENT COPILOT', hotkey: '3' },
  { key: 'fleet', label: 'HOSTS GRID', hotkey: '4' },
  { key: 'overview', label: 'OVERVIEW', sub: true },
  { key: 'inventory', label: 'INVENTORY', sub: true },
  { key: 'events', label: 'EVENTS', sub: true },
  { key: 'logs', label: 'LOGS', sub: true },
  { key: 'investigations', label: 'INVESTIGATIONS', sub: true },
];

export const REFRESH_OPTIONS = [
  { value: 5000, label: '5s' },
  { value: 10000, label: '10s' },
  { value: 30000, label: '30s' },
  { value: 0, label: 'off' },
];

function Clock() {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, []);
  return <span className="font-mono text-xs text-[#E8EAED]">{formatClock(now)}</span>;
}

const IconPulse = memo(() => (
  <svg width="10" height="10" viewBox="0 0 12 12" fill="none" aria-hidden="true">
    <circle cx="6" cy="6" r="4" fill="#C6FF00" />
    <circle cx="6" cy="6" r="5.5" stroke="#C6FF00" strokeOpacity="0.5" className="animate-ping" />
  </svg>
));

export function TopBar({
  view,
  setView,
  onToggleSettings,
  fleet,
  refreshMs,
  setRefreshMs,
  refreshing,
  onRefresh,
  query,
  setQuery,
}) {
  const isSettings = view === 'settings';

  const modes = [
    { id: 'observability', label: '1. OBSERVABILITY', hotkey: '1' },
    { id: 'pcap', label: '2. PCAP FORENSICS', hotkey: '2' },
    { id: 'agent', label: '3. AGENT COPILOT', hotkey: '3' },
    { id: 'fleet', label: 'HOSTS GRID', hotkey: '4' },
  ];

  return (
    <header className="bg-[#14171B] border border-[#262B32] rounded-[6px] px-4 py-2.5 shadow-[0_4px_16px_rgba(0,0,0,0.5)] flex flex-wrap items-center justify-between gap-3 sticky top-0 z-40">
      {/* Left: Brand Identity & Live Ingest Beacon */}
      <div className="flex items-center gap-3">
        <div
          className="flex items-center gap-2 px-2.5 py-1 bg-[#1B1F24] border border-[#262B32] rounded-[4px] cursor-pointer"
          onClick={() => setView('observability')}
          title="Live Telemetry Pipeline Active"
        >
          <IconPulse />
          <span className="font-mono text-[11px] font-bold text-[#E8EAED] uppercase tracking-wider">
            Live Ingest
          </span>
        </div>

        <div
          className="flex items-center cursor-pointer border-l border-[#262B32] pl-3"
          onClick={() => setView('observability')}
        >
          <span className="font-mono text-sm font-extrabold tracking-widest text-[#E8EAED]">
            PALANTIR
          </span>
          <span className="hidden sm:inline-block font-mono text-xs text-[#8B93A0] ml-2">
            // FORENSIC INSTRUMENT
          </span>
        </div>
      </div>

      {/* Center: Mode Switcher Tabs */}
      <nav className="flex items-center gap-1.5" role="tablist" aria-label="Forensic Instrument Modes">
        {modes.map((m) => {
          const isActive = view === m.id || (m.id === 'fleet' && ['overview', 'inventory', 'events', 'logs', 'investigations'].includes(view));
          return (
            <button
              key={m.id}
              role="tab"
              aria-selected={isActive}
              onClick={() => setView(m.id)}
              className={`px-3 py-1.5 text-xs font-mono font-bold uppercase rounded-[4px] transition-colors flex items-center gap-1.5 focus:outline-none ${
                isActive
                  ? 'bg-[#C6FF00] text-[#0A0B0D] font-extrabold shadow-[0_0_10px_rgba(198,255,0,0.3)]'
                  : 'text-[#8B93A0] hover:text-[#E8EAED] hover:bg-[#1B1F24]'
              }`}
            >
              <span>{m.label}</span>
              <span className={`text-[10px] px-1 rounded ${isActive ? 'bg-[#0A0B0D]/20 text-[#0A0B0D]' : 'bg-[#21262D] text-[#656C77]'}`}>
                {m.hotkey}
              </span>
            </button>
          );
        })}
      </nav>

      {/* Right: Chronometer, Fast Search, Settings */}
      <div className="flex items-center gap-2.5">
        <div className="font-mono text-xs text-[#8B93A0] px-2.5 py-1 bg-[#0A0B0D] border border-[#262B32] rounded-[4px]">
          <Clock />
        </div>

        <button
          className={`flex items-center gap-1.5 px-3 py-1.5 rounded-[4px] text-xs font-mono font-bold transition-all border ${
            isSettings
              ? 'bg-[#F5A524] text-[#0A0B0D] border-[#F5A524]'
              : 'bg-[#1B1F24] border-[#262B32] text-[#8B93A0] hover:text-[#E8EAED] hover:border-[#3D444F]'
          }`}
          onClick={onToggleSettings}
          title={isSettings ? 'Close Settings' : 'Open System Thresholds & Ops Diagnostics'}
        >
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
            <circle cx="12" cy="12" r="3" />
            <path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z" />
          </svg>
          <span>Settings</span>
        </button>
      </div>
    </header>
  );
}

export function NodeBar({ nodes, selectedId, onSelect, onAdd, onRemove, onViewGrid, currentView }) {
  return (
    <div className="flex items-center gap-2 overflow-x-auto py-1 font-mono text-xs">
      <button
        className={`px-2.5 py-1 rounded-[4px] border transition-colors ${
          currentView === 'fleet'
            ? 'bg-[#C6FF00] text-[#0A0B0D] border-[#C6FF00] font-bold'
            : 'bg-[#1B1F24] border-[#262B32] text-[#8B93A0] hover:text-[#E8EAED]'
        }`}
        onClick={onViewGrid}
        title="View All Monitored Target Hosts"
      >
        ⊞ Hosts Grid
      </button>

      <span className="text-[#656C77]">│</span>
      <span className="text-[#8B93A0]">Active Target:</span>

      {nodes.length === 0 && <span className="text-[#656C77]">none registered yet</span>}

      {nodes.map((n) => {
        const isSel = n.id === selectedId && currentView !== 'fleet';
        return (
          <button
            key={n.id}
            className={`px-2.5 py-1 rounded-[4px] border flex items-center gap-1.5 transition-colors ${
              isSel
                ? 'bg-[#1B1F24] border-[#C6FF00] text-[#C6FF00] font-bold'
                : 'bg-[#14171B] border-[#262B32] text-[#8B93A0] hover:text-[#E8EAED]'
            }`}
            onClick={() => onSelect(n.id)}
            title={`${n.collector_url || ''}\nLast contact ${formatRelative(n.last_seen_at)}`}
          >
            <Dot tone={statusTone(n.reachability)} />
            <span>{n.hostname}</span>
          </button>
        );
      })}

      <div className="flex-1" />

      {CAN_WRITE && (
        <div className="flex items-center gap-2">
          <button
            className="px-2.5 py-1 bg-[#1B1F24] border border-[#262B32] text-[#8B93A0] hover:text-[#E8EAED] rounded-[4px]"
            onClick={onAdd}
          >
            + Add Host
          </button>
          {selectedId && currentView !== 'fleet' && (
            <button
              className="px-2.5 py-1 bg-[rgba(229,72,77,0.12)] border border-[rgba(229,72,77,0.40)] text-[#FFA4A7] hover:bg-[rgba(229,72,77,0.25)] rounded-[4px]"
              onClick={onRemove}
            >
              Deactivate
            </button>
          )}
        </div>
      )}
    </div>
  );
}
