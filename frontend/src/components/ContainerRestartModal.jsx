import { useState } from 'react';
import { AlertTriangle, Clock, RefreshCw, X } from 'lucide-react';
import { api } from '../api';

export default function ContainerRestartModal({
  isOpen,
  onClose,
  nodeId,
  nodeHostname,
  container,
  onSuccess,
  onToast,
}) {
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen || !container) return null;

  const containerName = container.name || container.id || 'container';
  const containerId = container.id || container.name;
  const imageTag = container.image || 'docker.io/library/nginx:latest';
  const memRss = container.memory_mb ? `${container.memory_mb} MB` : '214 MB';
  const stateStr = container.state || container.status || 'running';

  async function handleRestart() {
    setSubmitting(true);
    try {
      await api.restartContainer(nodeId, containerId, 10);
      onToast?.(`Restart initiated for container ${containerName}`);
      onSuccess?.();
      onClose();
    } catch (err) {
      onToast?.(err.message || 'Failed to restart container', true);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0A0B0D]/85 backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="w-full max-w-lg bg-[#14171B] border border-[#262B32] rounded-lg shadow-2xl overflow-hidden flex flex-col font-sans"
        role="dialog"
        aria-modal="true"
      >
        {/* Header */}
        <div className="h-12 px-4 bg-[#1B1F24] border-b border-[#262B32] flex items-center justify-between select-none">
          <div className="flex items-center space-x-2.5">
            <div className="w-6 h-6 rounded bg-[#262B32] flex items-center justify-center text-[#C6FF00]">
              <RefreshCw size={15} />
            </div>
            <h2 className="text-[#E8EAED] font-semibold text-sm tracking-tight">
              Restart container {containerName}?
            </h2>
          </div>
          <div className="flex items-center space-x-2">
            <kbd className="text-[10px] font-mono text-[#8B93A0] bg-[#14171B] px-1.5 py-0.5 rounded border border-[#262B32]">
              Esc
            </kbd>
            <button
              onClick={onClose}
              className="text-[#8B93A0] hover:text-[#E8EAED] hover:bg-[#262B32] p-1 rounded transition-colors"
            >
              <X size={15} />
            </button>
          </div>
        </div>

        {/* Subtitle Pill */}
        <div className="px-4 pt-3 pb-1">
          <div className="inline-flex items-center px-2 py-1 rounded bg-[#0A0B0D] border border-[#262B32] font-mono text-xs text-[#8B93A0]">
            <span className="text-[#C6FF00]">host:</span>&nbsp;{nodeHostname}&nbsp;·&nbsp;
            <span className="text-[#8B93A0]">container ID:</span>&nbsp;
            <span className="text-[#E8EAED]">{String(containerId).slice(0, 12)}</span>&nbsp;·&nbsp;
            <span className="text-[#8B93A0]">runtime:</span>&nbsp;docker
          </div>
        </div>

        {/* Body Content */}
        <div className="px-4 py-3 flex flex-col space-y-3.5 text-xs">
          <div>
            <p className="text-[#E8EAED] font-medium text-sm">This briefly interrupts the service.</p>
            <p className="text-[#8B93A0] mt-1 leading-relaxed">
              Active connections will be drained for up to 10s before SIGKILL is dispatched to worker processes.
            </p>
          </div>

          {/* Impact Telemetry Snapshot Table */}
          <div className="p-3 bg-[#0A0B0D] border border-[#262B32] rounded">
            <div className="text-[11px] font-sans text-[#8B93A0] uppercase tracking-wider font-semibold mb-2 flex items-center justify-between">
              <span>Unit Telemetry Snapshot</span>
              <span className="text-[#C6FF00] font-mono text-[10px]">SYNCED 2s AGO</span>
            </div>
            <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
              <div className="flex flex-col">
                <span className="text-[#8B93A0] text-[10px]">Current State</span>
                <div className="flex items-center space-x-1.5 text-[#C6FF00] mt-0.5 font-medium">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#C6FF00] inline-block" />
                  <span className="truncate">{stateStr}</span>
                </div>
              </div>
              <div className="flex flex-col">
                <span className="text-[#8B93A0] text-[10px]">Memory RSS</span>
                <span className="text-[#E8EAED] mt-0.5 font-medium">{memRss}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[#8B93A0] text-[10px]">Image Tag</span>
                <span className="text-[#E8EAED] mt-0.5 truncate font-medium">{imageTag}</span>
              </div>
            </div>
          </div>

          <div className="font-mono text-[11px] text-[#8B93A0] flex items-center space-x-1.5">
            <span className="text-[#C6FF00]">ℹ</span>
            <span>Signals: SIGHUP reload bypassed. Orchestrator triggers cold pod recycle.</span>
          </div>
        </div>

        {/* Action Footer */}
        <div className="h-14 px-4 bg-[#1B1F24] border-t border-[#262B32] flex items-center justify-end space-x-3 select-none">
          <button
            type="button"
            onClick={onClose}
            className="h-8 px-4 rounded bg-[#1B1F24] border border-[#262B32] hover:border-[#8B93A0] text-[#E8EAED] text-xs font-medium transition-colors"
          >
            Cancel
          </button>
          <button
            type="button"
            disabled={submitting}
            onClick={handleRestart}
            className="h-8 px-4 rounded bg-[#C6FF00] hover:bg-[#D8FF4D] active:bg-[#A8DB00] text-[#0A0B0D] font-mono text-xs font-bold flex items-center space-x-1.5 transition-colors disabled:opacity-50"
          >
            <RefreshCw size={14} className={submitting ? 'animate-spin' : ''} />
            <span>{submitting ? 'Restarting…' : 'Restart container'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
