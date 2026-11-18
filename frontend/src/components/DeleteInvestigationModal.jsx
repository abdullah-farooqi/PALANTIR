import { useState } from 'react';
import { AlertTriangle, Shield, Trash2, X } from 'lucide-react';
import { api } from '../api';

export default function DeleteInvestigationModal({
  isOpen,
  onClose,
  investigation,
  onSuccess,
  onToast,
}) {
  const [confirmText, setConfirmText] = useState('');
  const [deleting, setDeleting] = useState(false);

  if (!isOpen || !investigation) return null;

  const targetHostname = investigation.hostname || (investigation.node && investigation.node.hostname) || 'web-01';
  const jobId = investigation.job_id || `inv_${investigation.id}`;
  const isConfirmed = confirmText.trim() === targetHostname;

  async function handleDelete() {
    if (!isConfirmed) return;
    setDeleting(true);
    try {
      await api.deleteInvestigation(investigation.id);
      onToast?.(`Investigation #${investigation.id} expunged successfully`);
      onSuccess?.(investigation.id);
      onClose();
    } catch (err) {
      onToast?.(err.message || 'Failed to delete investigation', true);
    } finally {
      setDeleting(false);
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
        {/* Top Status Strip */}
        <div className="h-1 w-full bg-[#E5484D]" />

        {/* Header */}
        <div className="px-6 pt-5 pb-4 bg-[#1B1F24] flex items-center justify-between border-b border-[#262B32]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded bg-[#E5484D]/20 flex items-center justify-center text-[#E5484D]">
              <Trash2 size={18} />
            </div>
            <div className="flex flex-col">
              <div className="flex items-center gap-2">
                <h2 className="text-[#E8EAED] font-semibold text-sm tracking-tight">
                  Delete this investigation?
                </h2>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-[#E5484D]/30 text-[#E5484D] font-mono font-bold uppercase">
                  IRREVERSIBLE
                </span>
              </div>
              <span className="text-[11px] font-mono text-[#8B93A0]">
                REF: {jobId.toUpperCase()} • HOST: {targetHostname}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <kbd className="text-[10px] font-mono bg-[#0A0B0D] px-1.5 py-0.5 rounded text-[#8B93A0] border border-[#262B32]">
              Esc
            </kbd>
            <button
              onClick={onClose}
              className="w-7 h-7 rounded flex items-center justify-center text-[#8B93A0] hover:text-[#E8EAED] hover:bg-[#262B32]"
            >
              <X size={16} />
            </button>
          </div>
        </div>

        {/* Body Content */}
        <div className="p-6 space-y-4 bg-[#14171B] text-xs">
          {/* Critical Warning Box */}
          <div className="p-3.5 rounded bg-[#0A0B0D] border border-[#262B32] flex flex-col gap-2.5">
            <div className="flex items-start gap-2.5">
              <AlertTriangle size={18} className="text-[#E5484D] shrink-0 mt-0.5" />
              <div className="flex flex-col gap-1">
                <p className="text-[#E8EAED] font-medium leading-snug">
                  Job <span className="font-mono text-[#C6FF00]">{jobId}</span> and all associated evidence will be expunged immediately. This action cannot be rolled back or restored.
                </p>
                <p className="text-[#8B93A0] leading-relaxed">
                  Purging this container terminates running background forensic replay workers and erases captured ephemeral host artifacts.
                </p>
              </div>
            </div>

            {/* Expunged Items Breakdown */}
            <div className="bg-[#14171B] rounded p-3 space-y-2 mt-1 border border-[#262B32]/50">
              <div className="text-[11px] text-[#8B93A0] uppercase font-semibold">
                Target Evidence Slated for Zeroization:
              </div>
              <ul className="space-y-1.5 font-mono text-[11px] text-[#E8EAED]">
                <li className="flex items-center justify-between">
                  <span className="text-[#8B93A0]">eBPF Telemetry Snapshots (ring events)</span>
                  <span className="text-[#8B93A0] text-[10px]">RAM BUFFER</span>
                </li>
                <li className="flex items-center justify-between">
                  <span className="text-[#8B93A0]">Network PCAP captures & flows</span>
                  <span className="text-[#8B93A0] text-[10px]">STORAGE</span>
                </li>
                <li className="flex items-center justify-between">
                  <span className="text-[#8B93A0]">IOC correlations & CVE matches</span>
                  <span className="text-[#8B93A0] text-[10px]">RELATIONAL DB</span>
                </li>
              </ul>
            </div>
          </div>

          {/* Audit Stamp */}
          <div className="flex items-center gap-2 px-3 py-2 bg-[#0A0B0D] border border-[#262B32] rounded text-[#8B93A0]">
            <Shield size={14} className="text-[#C6FF00]" />
            <div className="text-[11px]">
              Action logged under operator <span className="font-mono text-[#E8EAED] font-semibold">e.vance (L3 SOC)</span> to SIEM ledger.
            </div>
          </div>

          {/* Type-to-Confirm Input */}
          <div className="flex flex-col gap-2 pt-1">
            <div className="flex justify-between items-baseline">
              <label className="text-[#E8EAED] font-semibold text-xs">
                Type <span className="font-mono text-[#C6FF00] bg-[#0A0B0D] px-1.5 py-0.5 rounded border border-[#262B32] font-bold">{targetHostname}</span> to confirm
              </label>
              <span className="text-[10px] font-mono text-[#8B93A0]">CASE-SENSITIVE</span>
            </div>

            <div className="relative flex items-center">
              <span className="absolute left-3 font-mono text-[#8B93A0] select-none font-bold text-sm">&gt;_</span>
              <input
                type="text"
                value={confirmText}
                onChange={(e) => setConfirmText(e.target.value)}
                placeholder="Type target hostname..."
                className="w-full h-9 pl-9 pr-4 bg-[#0A0B0D] border border-[#262B32] rounded text-[#E8EAED] font-mono text-xs focus:border-[#E5484D] focus:outline-none"
              />
            </div>
          </div>
        </div>

        {/* Action Footer */}
        <div className="px-6 py-4 bg-[#1B1F24] border-t border-[#262B32] flex items-center justify-between">
          <div className="flex items-center gap-1.5 text-[#8B93A0] font-mono text-[11px]">
            <Shield size={13} />
            <span>PROTECTED WORKFLOW</span>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onClose}
              className="h-8 px-4 rounded bg-[#1B1F24] border border-[#262B32] hover:border-[#8B93A0] text-[#E8EAED] text-xs font-medium transition-colors"
            >
              Cancel
            </button>
            <button
              type="button"
              disabled={!isConfirmed || deleting}
              onClick={handleDelete}
              className="h-8 px-4 rounded bg-[#E5484D] hover:bg-[#FF6B6B] text-[#0A0B0D] font-mono text-xs font-bold transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {deleting ? 'Expunging…' : 'Expunge Investigation'}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
