import React from 'react';
import { REFRESH_OPTIONS } from './Layout';
import { Dot, Empty, ErrorLine } from './ui';
import { AGENT } from '../lib/metrics';
import { formatRelative } from '../lib/format';
import { statusTone } from '../lib/events';

export default function SettingsTab({ node, data, refreshMs, setRefreshMs, onRefresh, refreshing, onBack }) {
  const cats = (data && data.status && data.status.categories) || [];
  const age = (iso) => (iso ? formatRelative(iso) : '—');

  const cell = (c, source) => {
    const s = (c.sources || []).find((x) => x.source === source);
    if (!s) return <span className="tone-dim">—</span>;
    const tone = statusTone(s.status);
    return (
      <span title={`${s.status}${s.error_message ? ` — ${s.error_message}` : ''}`} className="row" style={{ gap: 5 }}>
        <Dot tone={tone} />
        <span className={tone === 'dim' ? 'tone-dim' : ''}>{s.status === 'available' ? age(s.last_success_at) : s.status.replace('_', ' ')}</span>
      </span>
    );
  };

  return (
    <div className="settings-page-wrapper" style={{ padding: '24px 32px', maxWidth: '960px', margin: '0 auto' }}>
      <div className="settings-header-bar" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button className="btn primary sm" onClick={onBack} style={{ fontSize: '14px', padding: '6px 14px' }}>
            ← Back to Fleet Grid
          </button>
          <h2 style={{ fontSize: '24px', fontWeight: 800, color: '#39e569', margin: 0 }}>System Settings & Sources</h2>
        </div>
      </div>

      {/* Card 1: Telemetry Refresh Settings */}
      <div className="settings-card-section" style={{ background: '#080d09', border: '1.5px solid #193822', borderRadius: '16px', padding: '24px', marginBottom: '24px', boxShadow: '0 0 20px rgba(20,50,25,0.25)' }}>
        <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff', marginTop: 0, marginBottom: '8px' }}>
          Telemetry Polling Refresh Rate
        </h3>
        <p style={{ color: '#7a9680', fontSize: '13.5px', marginBottom: '20px' }}>
          Configure how frequently central workers fetch live CPU, memory, storage, and network snapshots from target host agents.
        </p>

        <div className="refresh-options-grid" style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '14px', marginBottom: '20px' }}>
          {REFRESH_OPTIONS.map((option) => {
            const isSelected = refreshMs === option.value;
            return (
              <div
                key={option.value}
                onClick={() => setRefreshMs(option.value)}
                style={{
                  background: isSelected ? 'rgba(57, 229, 105, 0.12)' : '#0d1710',
                  border: isSelected ? '2px solid #39e569' : '1px solid #1c3823',
                  borderRadius: '12px',
                  padding: '16px',
                  cursor: 'pointer',
                  textAlign: 'center',
                  transition: 'all 0.2s ease',
                  boxShadow: isSelected ? '0 0 15px rgba(57, 229, 105, 0.2)' : 'none',
                }}
              >
                <div style={{ fontSize: '20px', fontWeight: 800, color: isSelected ? '#39e569' : '#fff', marginBottom: '4px' }}>
                  {option.label}
                </div>
                <div style={{ fontSize: '12px', color: isSelected ? '#a3e635' : '#6a8a71', fontWeight: 600 }}>
                  {option.value === 0 ? 'Manual Refresh Only' : `Every ${option.value / 1000} Seconds`}
                </div>
              </div>
            );
          })}
        </div>

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', paddingTop: '16px', borderTop: '1px solid #162c1d' }}>
          <span style={{ color: '#8aa690', fontSize: '13px' }}>Force Immediate Telemetry Synchronization:</span>
          <button
            className="btn primary"
            onClick={onRefresh}
            style={{ padding: '8px 18px', fontSize: '13.5px', borderRadius: '8px' }}
          >
            {refreshing ? 'Synchronizing...' : 'Refresh Now'}
          </button>
        </div>
      </div>

      {/* Card 2: Collector Pipeline & Sources Status */}
      <div className="settings-card-section" style={{ background: '#080d09', border: '1.5px solid #193822', borderRadius: '16px', padding: '24px', boxShadow: '0 0 20px rgba(20,50,25,0.25)' }}>
        <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff', marginTop: 0, marginBottom: '8px' }}>
          Telemetry Collection Sources
        </h3>
        <p style={{ color: '#7a9680', fontSize: '13.5px', marginBottom: '16px' }}>
          Status of telemetry categories collected by the PALANTIR host collector.
        </p>

        {data && data.errors && data.errors.status && <ErrorLine warn>collection-status: {data.errors.status}</ErrorLine>}

        {cats.length === 0 ? (
          <Empty>No collection status telemetry available yet.</Empty>
        ) : (
          <div className="box-scroll" style={{ overflowX: 'auto', marginBottom: 16 }}>
            <table className="tbl">
              <thead>
                <tr>
                  <th />
                  {cats.map((c) => <th key={c.category}>{c.label || c.category}</th>)}
                </tr>
              </thead>
              <tbody>
                <tr><td className="tone-dim" style={{ fontWeight: 700, color: '#a3c4aa' }}>collector</td>{cats.map((c) => <td key={c.category}>{cell(c, AGENT)}</td>)}</tr>
              </tbody>
            </table>
          </div>
        )}

        {node && (
          <div style={{ paddingTop: 12, borderTop: '1px solid #142e1a', color: '#728c78', fontSize: 12, fontFamily: 'JetBrains Mono, monospace' }}>
            <div>last contact: <span style={{ color: '#d8dee9' }}>{formatRelative(node.last_seen_at)}</span> • last collection: <span style={{ color: '#d8dee9' }}>{formatRelative(node.last_collection_at)}</span></div>
            <div style={{ marginTop: 4 }}>collector: <span style={{ color: '#06b6d4' }}>{node.collector_url || 'not configured'}</span></div>
          </div>
        )}
      </div>
    </div>
  );
}
