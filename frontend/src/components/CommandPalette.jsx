import { useEffect, useRef, useState } from 'react';
import {
  Activity, AlertTriangle, ArrowRight, CornerDownLeft, FileDown,
  LayoutDashboard, Logs, Plus, Search, Server, Settings2, ShieldCheck,
  Sparkles, X,
} from 'lucide-react';

export default function CommandPalette({
  isOpen,
  onClose,
  nodes = [],
  onSelectNode,
  onChangeView,
  onAddNode,
  onTriggerIngest,
  onExportAlerts,
}) {
  const [query, setQuery] = useState('');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const inputRef = useRef(null);

  useEffect(() => {
    if (isOpen) {
      setQuery('');
      setSelectedIndex(0);
      setTimeout(() => inputRef.current?.focus(), 50);
    }
  }, [isOpen]);

  useEffect(() => {
    function handleKeyDown(e) {
      if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
        e.preventDefault();
        if (isOpen) onClose();
        else onClose(false); // will trigger toggle in parent
      }
      if (!isOpen) return;
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
      }
    }
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

  if (!isOpen) return null;

  const q = query.toLowerCase().trim();

  // Navigation commands
  const navCommands = [
    { id: 'nav-fleet-overview', label: 'Go to Fleet Overview', group: 'Navigation', icon: LayoutDashboard, action: () => { onChangeView('fleet-overview'); onClose(); } },
    { id: 'nav-hosts', label: 'Go to Hosts Fleet Grid / Table', group: 'Navigation', icon: Server, action: () => { onChangeView('fleet'); onClose(); } },
    { id: 'nav-alerts', label: 'Go to Alerts & Events Triage', group: 'Navigation', icon: AlertTriangle, action: () => { onChangeView('events'); onClose(); } },
    { id: 'nav-logs', label: 'Go to Live Fleet Logs', group: 'Navigation', icon: Logs, action: () => { onChangeView('logs'); onClose(); } },
    { id: 'nav-investigations', label: 'Go to Security Investigations', group: 'Navigation', icon: ShieldCheck, action: () => { onChangeView('investigations'); onClose(); } },
    { id: 'nav-pcap', label: 'Go to Network Evidence & PCAP', group: 'Navigation', icon: Activity, action: () => { onChangeView('pcap'); onClose(); } },
    { id: 'nav-copilot', label: 'Go to Copilot Preview (AI Assistant)', group: 'Navigation', icon: Sparkles, action: () => { onChangeView('agent'); onClose(); } },
    { id: 'nav-settings', label: 'Go to System Settings', group: 'Navigation', icon: Settings2, action: () => { onChangeView('settings'); onClose(); } },
  ];

  // Actions commands
  const actionCommands = [
    { id: 'act-add-node', label: 'Register New Host Node', group: 'Actions', icon: Plus, action: () => { onAddNode?.(); onClose(); } },
    { id: 'act-ingest', label: 'Trigger Telemetry Ingest', group: 'Actions', icon: Activity, action: () => { onTriggerIngest?.(); onClose(); } },
    { id: 'act-export', label: 'Export Fleet Alerts (STIX 2.1)', group: 'Actions', icon: FileDown, action: () => { onExportAlerts?.(); onClose(); } },
  ];

  // Node commands
  const nodeCommands = nodes.map((node) => ({
    id: `node-${node.id}`,
    label: `Jump to Host: ${node.hostname}`,
    sub: `${node.collector_url || 'no-collector'} · OS: ${node.os_type || 'linux'}`,
    group: 'Hosts',
    icon: Server,
    action: () => {
      onSelectNode(node.id);
      onClose();
    },
  }));

  const allItems = [
    ...nodeCommands.filter((c) => !q || c.label.toLowerCase().includes(q) || (c.sub && c.sub.toLowerCase().includes(q))),
    ...navCommands.filter((c) => !q || c.label.toLowerCase().includes(q)),
    ...actionCommands.filter((c) => !q || c.label.toLowerCase().includes(q)),
  ];

  function handleInputKeyDown(e) {
    if (e.key === 'ArrowDown') {
      e.preventDefault();
      setSelectedIndex((prev) => (allItems.length ? (prev + 1) % allItems.length : 0));
    } else if (e.key === 'ArrowUp') {
      e.preventDefault();
      setSelectedIndex((prev) => (allItems.length ? (prev - 1 + allItems.length) % allItems.length : 0));
    } else if (e.key === 'Enter') {
      e.preventDefault();
      if (allItems[selectedIndex]) {
        allItems[selectedIndex].action();
      }
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-20 bg-black/75 backdrop-blur-sm"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="w-full max-w-xl bg-[#14171B] border border-[#262B32] rounded-lg shadow-2xl overflow-hidden flex flex-col animate-in fade-in zoom-in-95 duration-100"
        role="dialog"
        aria-modal="true"
      >
        <div className="flex items-center px-4 py-3 border-b border-[#262B32] bg-[#1B1F24]">
          <span className="font-mono text-[#C6FF00] font-bold text-sm mr-2">&gt;_</span>
          <Search size={16} className="text-[#8B93A0] mr-2" />
          <input
            ref={inputRef}
            type="text"
            className="flex-1 bg-transparent border-none text-[#E8EAED] font-mono text-sm placeholder:text-[#8B93A0] focus:outline-none"
            placeholder="Quick command or jump to host... (e.g. web-01, copilot, alerts)"
            value={query}
            onChange={(e) => {
              setQuery(e.target.value);
              setSelectedIndex(0);
            }}
            onKeyDown={handleInputKeyDown}
          />
          <kbd className="px-1.5 py-0.5 text-[10px] font-mono bg-[#0A0B0D] border border-[#262B32] text-[#8B93A0] rounded">
            Esc
          </kbd>
        </div>

        <div className="max-h-80 overflow-y-auto p-2 space-y-1">
          {allItems.length === 0 ? (
            <div className="px-4 py-8 text-center text-[#8B93A0] font-mono text-xs">
              No matching hosts, views, or commands found.
            </div>
          ) : (
            allItems.map((item, idx) => {
              const Icon = item.icon;
              const isSelected = idx === selectedIndex;
              return (
                <button
                  key={item.id}
                  type="button"
                  onClick={item.action}
                  onMouseEnter={() => setSelectedIndex(idx)}
                  className={`w-full text-left px-3 py-2 rounded flex items-center justify-between text-xs font-sans transition-colors ${
                    isSelected
                      ? 'bg-[#C6FF00]/10 text-[#C6FF00] border-l-2 border-[#C6FF00]'
                      : 'text-[#E8EAED] hover:bg-[#1B1F24]'
                  }`}
                >
                  <div className="flex items-center gap-2.5 truncate">
                    <Icon size={15} className={isSelected ? 'text-[#C6FF00]' : 'text-[#8B93A0]'} />
                    <span className="font-medium truncate">{item.label}</span>
                    {item.sub && (
                      <span className="text-[11px] font-mono text-[#8B93A0] truncate">({item.sub})</span>
                    )}
                  </div>
                  <div className="flex items-center gap-2 text-[#8B93A0]">
                    <span className="text-[10px] font-mono uppercase bg-[#0A0B0D] px-1.5 py-0.5 rounded border border-[#262B32]">
                      {item.group}
                    </span>
                    {isSelected && <CornerDownLeft size={12} className="text-[#C6FF00]" />}
                  </div>
                </button>
              );
            })
          )}
        </div>

        <div className="px-4 py-2 bg-[#0A0B0D] border-t border-[#262B32] flex items-center justify-between text-[11px] font-mono text-[#8B93A0]">
          <div className="flex items-center gap-3">
            <span>↑↓ Navigate</span>
            <span>↵ Select</span>
            <span>Esc Dismiss</span>
          </div>
          <span className="text-[#C6FF00]">PALANTIR COMMAND PALETTE</span>
        </div>
      </div>
    </div>
  );
}
