import { useEffect, useState } from 'react';
import { Check, Filter, Layers, Search, Shield, Sliders, X } from 'lucide-react';
import { api } from '../api';

export default function RuleMatrixModal({ isOpen, onClose, onToast }) {
  const [rules, setRules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [query, setQuery] = useState('');
  const [categoryFilter, setCategoryFilter] = useState('all');

  useEffect(() => {
    if (isOpen) {
      loadRules();
    }
  }, [isOpen]);

  async function loadRules() {
    setLoading(true);
    try {
      const res = await api.getDetectionRules();
      setRules(res.rules || []);
    } catch (err) {
      onToast?.(err.message || 'Failed to load detection rules', true);
    } finally {
      setLoading(false);
    }
  }

  if (!isOpen) return null;

  const filteredRules = rules.filter((r) => {
    const matchesQ =
      !query ||
      r.name.toLowerCase().includes(query.toLowerCase()) ||
      r.condition.toLowerCase().includes(query.toLowerCase()) ||
      r.chart.toLowerCase().includes(query.toLowerCase());
    const matchesCat = categoryFilter === 'all' || r.category === categoryFilter;
    return matchesQ && matchesCat;
  });

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-[#0A0B0D]/85 backdrop-blur-[2px]"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) onClose();
      }}
    >
      <div
        className="w-full max-w-4xl bg-[#14171B] border border-[#262B32] rounded-lg shadow-2xl overflow-hidden flex flex-col max-h-[85vh] font-sans"
        role="dialog"
        aria-modal="true"
      >
        {/* Header */}
        <div className="h-12 px-6 bg-[#1B1F24] border-b border-[#262B32] flex items-center justify-between select-none">
          <div className="flex items-center space-x-2.5">
            <div className="w-6 h-6 rounded bg-[#262B32] flex items-center justify-center text-[#C6FF00]">
              <Sliders size={15} />
            </div>
            <h2 className="text-[#E8EAED] font-semibold text-sm tracking-tight">
              Rule Matrix & Detection Engine (312 Rules Loaded)
            </h2>
          </div>
          <button
            onClick={onClose}
            className="text-[#8B93A0] hover:text-[#E8EAED] hover:bg-[#262B32] p-1 rounded transition-colors"
          >
            <X size={16} />
          </button>
        </div>

        {/* Filter bar */}
        <div className="p-4 bg-[#1B1F24]/50 border-b border-[#262B32] flex flex-wrap items-center justify-between gap-3 text-xs">
          <div className="relative flex-1 max-w-md">
            <Search size={14} className="absolute left-3 top-2.5 text-[#8B93A0]" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search detection rules (e.g. CPU, oomkill, socket drops)..."
              className="w-full h-8 pl-8 pr-3 bg-[#0A0B0D] border border-[#262B32] rounded text-[#E8EAED] font-mono text-xs focus:border-[#C6FF00] focus:outline-none"
            />
          </div>

          <div className="flex items-center gap-1 font-mono text-xs">
            {['all', 'system', 'network', 'storage', 'processes', 'connections'].map((cat) => (
              <button
                key={cat}
                type="button"
                onClick={() => setCategoryFilter(cat)}
                className={`h-7 px-2.5 rounded transition-colors uppercase text-[11px] font-semibold ${
                  categoryFilter === cat
                    ? 'bg-[#C6FF00] text-[#0A0B0D]'
                    : 'bg-[#14171B] border border-[#262B32] text-[#8B93A0] hover:text-[#E8EAED]'
                }`}
              >
                {cat}
              </button>
            ))}
          </div>
        </div>

        {/* Rules Table */}
        <div className="flex-1 overflow-y-auto p-4">
          <div className="bg-[#0A0B0D] border border-[#262B32] rounded overflow-hidden">
            <table className="w-full text-left border-collapse text-xs">
              <thead>
                <tr className="h-8 bg-[#1B1F24] border-b border-[#262B32] text-[#8B93A0] font-mono uppercase text-[11px]">
                  <th className="px-3 py-1">Rule Name</th>
                  <th className="px-3 py-1">Category</th>
                  <th className="px-3 py-1">Metric / Chart</th>
                  <th className="px-3 py-1">Severity</th>
                  <th className="px-3 py-1">Condition Threshold</th>
                  <th className="px-3 py-1 text-center">Active</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#262B32]/60 font-mono text-xs text-[#E8EAED]">
                {loading ? (
                  <tr>
                    <td colSpan={6} className="text-center py-8 text-[#8B93A0]">
                      Loading detection rule matrix…
                    </td>
                  </tr>
                ) : filteredRules.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="text-center py-8 text-[#8B93A0]">
                      No rules matched the filter criteria.
                    </td>
                  </tr>
                ) : (
                  filteredRules.map((r) => {
                    const isCrit = r.severity === 'CRITICAL';
                    return (
                      <tr key={r.id} className="h-9 hover:bg-[#1B1F24] transition-colors">
                        <td className="px-3 py-1.5 font-semibold text-[#E8EAED]">
                          <div>{r.name}</div>
                          <div className="text-[10px] text-[#8B93A0] font-sans font-normal truncate max-w-xs">
                            {r.description}
                          </div>
                        </td>
                        <td className="px-3 py-1.5 uppercase text-[11px] text-[#8B93A0]">{r.category}</td>
                        <td className="px-3 py-1.5 text-[#C6FF00]">{r.chart}</td>
                        <td className="px-3 py-1.5">
                          <span
                            className={`px-1.5 py-0.5 rounded text-[10px] font-bold ${
                              isCrit ? 'bg-[#E5484D]/20 text-[#E5484D]' : 'bg-[#F5A524]/20 text-[#F5A524]'
                            }`}
                          >
                            {r.severity}
                          </span>
                        </td>
                        <td className="px-3 py-1.5 text-[#E8EAED] font-bold">{r.condition}</td>
                        <td className="px-3 py-1.5 text-center">
                          <span className="inline-flex items-center px-1.5 py-0.5 rounded bg-[#C6FF00]/10 text-[#C6FF00] text-[10px] font-bold">
                            ENABLED
                          </span>
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <div className="h-12 px-6 bg-[#1B1F24] border-t border-[#262B32] flex items-center justify-between text-xs font-mono text-[#8B93A0]">
          <span>Showing {filteredRules.length} of {rules.length} total active rules</span>
          <button
            type="button"
            onClick={onClose}
            className="h-8 px-4 rounded bg-[#C6FF00] text-[#0A0B0D] font-bold hover:bg-[#D8FF4D]"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
}
