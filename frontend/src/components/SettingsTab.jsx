import React from 'react';
import { REFRESH_OPTIONS } from './Layout';
import { CAN_WRITE, UI_ROLE } from '../lib/role';

export default function SettingsTab({ refreshMs, setRefreshMs, onRefresh, refreshing, onBack }) {
  return (
    <div className="settings-page-wrapper" style={{ padding: '24px 32px', maxWidth: '900px', margin: '0 auto' }}>
      <div className="settings-header-bar" style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '24px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
          <button className="btn primary sm" onClick={onBack} style={{ fontSize: '14px', padding: '6px 14px' }}>
            ← Back to Fleet Grid
          </button>
          <h2 style={{ fontSize: '24px', fontWeight: 800, color: '#39e569', margin: 0 }}>System Control & Settings</h2>
        </div>
      </div>

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

      <div className="settings-card-section" style={{ background: '#080d09', border: '1.5px solid #193822', borderRadius: '16px', padding: '24px', boxShadow: '0 0 20px rgba(20,50,25,0.25)' }}>
        <h3 style={{ fontSize: '18px', fontWeight: 700, color: '#fff', marginTop: 0, marginBottom: '8px' }}>
          System Role & Authorization
        </h3>
        <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginTop: '16px' }}>
          <div style={{ background: 'rgba(50, 40, 20, 0.8)', border: '1px solid #7a612d', padding: '10px 18px', borderRadius: '10px', color: '#e5c07b', fontWeight: 800, fontSize: '16px' }}>
            ROLE: {UI_ROLE === 'none' ? 'GUEST' : UI_ROLE.toUpperCase()}
          </div>
          <div style={{ color: '#8aa690', fontSize: '13.5px' }}>
            {CAN_WRITE
              ? 'Administrator privilege active: Full access to add, configure, and manage target host nodes.'
              : 'Read-only access mode: Viewing telemetry metrics and diagnostic logs.'}
          </div>
        </div>
      </div>
    </div>
  );
}
