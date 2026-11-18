import { useState } from 'react';
import { AlertOctagon, PowerOff, X } from 'lucide-react';
import { api } from '../api';

export default function VmStopModal({
  isOpen,
  onClose,
  nodeId,
  nodeHostname,
  vm,
  onSuccess,
  onToast,
}) {
  const [submitting, setSubmitting] = useState(false);

  if (!isOpen || !vm) return null;

  const vmName = vm.name || vm.id || 'virtual-machine';
  const vmId = vm.id || vm.name;
  const hypervisor = vm.hypervisor || 'QEMU/KVM';
  const memAlloc = vm.memory_mb ? `${vm.memory_mb} MB` : '8,192 MB (64%)';
  const stateStr = vm.state || vm.status || 'healthy';

  async function handleStop() {
    setSubmitting(true);
    try {
      await api.stopVm(nodeId, vmId, false);
      onToast?.(`Stop command dispatched to VM ${vmName}`);
      onSuccess?.();
      onClose();
    } catch (err) {
      onToast?.(err.message || 'Failed to stop VM', true);
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
            <div className="w-6 h-6 rounded bg-[#262B32] flex items-center justify-center text-[#E5484D]">
              <PowerOff size={15} />
            </div>
            <h2 className="text-[#E8EAED] font-semibold text-sm tracking-tight">
              Stop virtual machine {vmName}?
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
            <span className="text-[#8B93A0]">VM ID:</span>&nbsp;
            <span className="text-[#E8EAED]">{String(vmId).slice(0, 14)}</span>&nbsp;·&nbsp;
            <span className="text-[#8B93A0]">hypervisor:</span>&nbsp;{hypervisor}
          </div>
        </div>

        {/* Body Content */}
        <div className="px-4 py-3 flex flex-col space-y-3.5 text-xs">
          <div>
            <p className="text-[#E8EAED] font-medium text-sm">Graceful ACPI shutdown dispatched.</p>
            <p className="text-[#8B93A0] mt-1 leading-relaxed">
              Guest operating system is given 30 seconds to flush disk buffers before a hard power cut (SIGTERM to QEMU monitor).
            </p>
          </div>

          {/* Impact Telemetry Snapshot Table */}
          <div className="p-3 bg-[#0A0B0D] border border-[#262B32] rounded">
            <div className="text-[11px] font-sans text-[#8B93A0] uppercase tracking-wider font-semibold mb-2 flex items-center justify-between">
              <span>Hypervisor Telemetry Snapshot</span>
              <span className="text-[#C6FF00] font-mono text-[10px]">ACTIVE</span>
            </div>
            <div className="grid grid-cols-3 gap-2 font-mono text-[11px]">
              <div className="flex flex-col">
                <span className="text-[#8B93A0] text-[10px]">State</span>
                <div className="flex items-center space-x-1.5 text-[#C6FF00] mt-0.5 font-medium">
                  <span className="w-1.5 h-1.5 rounded-full bg-[#C6FF00] inline-block" />
                  <span className="truncate">{stateStr}</span>
                </div>
              </div>
              <div className="flex flex-col">
                <span className="text-[#8B93A0] text-[10px]">Allocated RAM</span>
                <span className="text-[#E8EAED] mt-0.5 font-medium">{memAlloc}</span>
              </div>
              <div className="flex flex-col">
                <span className="text-[#8B93A0] text-[10px]">Engine</span>
                <span className="text-[#E8EAED] mt-0.5 truncate font-medium">{hypervisor}</span>
              </div>
            </div>
          </div>

          <div className="font-mono text-[11px] text-[#8B93A0] flex items-center space-x-1.5">
            <span className="text-[#E5484D]">⚠</span>
            <span>Uncommitted write caches inside the guest OS may be lost if ACPI is ignored.</span>
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
            onClick={handleStop}
            className="h-8 px-4 rounded bg-[#E5484D] hover:bg-[#FF6B6B] active:bg-[#C92A2A] text-[#0A0B0D] font-mono text-xs font-bold flex items-center space-x-1.5 transition-colors disabled:opacity-50"
          >
            <PowerOff size={14} className={submitting ? 'animate-spin' : ''} />
            <span>{submitting ? 'Stopping…' : 'Stop virtual machine'}</span>
          </button>
        </div>
      </div>
    </div>
  );
}
