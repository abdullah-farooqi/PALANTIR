import React from 'react';

const TABS = [
  { key: 'overview', label: 'OVERVIEW' },
  { key: 'inventory', label: 'INVENTORY' },
  { key: 'events', label: 'ALERTS & EVENTS' },
  { key: 'logs', label: 'LOGS' },
  { key: 'investigations', label: 'INVESTIGATIONS' },
];

export default function NodeHeaderNav({ node, currentView, onViewChange, onBack }) {
  const rawAddr = node?.collector_url ? node.collector_url.replace(/^https?:\/\//, '').replace(/\/.*$/, '') : '';
  const hostIp = rawAddr.endsWith(':20000') ? rawAddr.replace(':20000', '') : rawAddr;

  return (
    <div
      className="node-header-nav"
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        marginBottom: 12,
        padding: '10px 16px',
        background: '#080d09',
        borderRadius: 10,
        border: '1.5px solid #193822',
        flexWrap: 'wrap',
        gap: 12,
      }}
    >
      {/* Left: Back button + Hostname + IP */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        {onBack && (
          <button
            className="btn primary"
            onClick={onBack}
            title="Return to Fleet Grid"
            style={{
              width: 38,
              height: 38,
              padding: 0,
              display: 'inline-flex',
              alignItems: 'center',
              justifyContent: 'center',
              borderRadius: 8,
              fontSize: 20,
              fontWeight: 'bold',
            }}
          >
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="19" y1="12" x2="5" y2="12"></line>
              <polyline points="12 19 5 12 12 5"></polyline>
            </svg>
          </button>
        )}
        <span style={{ fontSize: '1.25rem', fontWeight: 800, color: '#fff' }}>
          {node?.hostname || 'Host Details'}
        </span>
        {hostIp && (
          <span className="tone-dim" style={{ fontSize: '0.9rem', fontFamily: 'JetBrains Mono, monospace' }}>
            {hostIp}
          </span>
        )}
      </div>

      {/* Right: Quick Tab Navigation Buttons */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
        {TABS.map((tab) => {
          const isActive = currentView === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => onViewChange(tab.key)}
              style={{
                background: isActive ? 'rgba(57, 229, 105, 0.16)' : '#0d1a10',
                border: isActive ? '1.5px solid #39e569' : '1px solid #1c3823',
                color: isActive ? '#39e569' : '#88a08d',
                borderRadius: 7,
                padding: '6px 12px',
                fontSize: 11.5,
                fontWeight: 700,
                letterSpacing: '0.04em',
                cursor: 'pointer',
                transition: 'all 0.15s ease',
                fontFamily: 'JetBrains Mono, monospace',
                boxShadow: isActive ? '0 0 10px rgba(57, 229, 105, 0.22)' : 'none',
              }}
              onMouseEnter={(e) => {
                if (!isActive) {
                  e.currentTarget.style.borderColor = '#2d6b3c';
                  e.currentTarget.style.color = '#c6f6d5';
                }
              }}
              onMouseLeave={(e) => {
                if (!isActive) {
                  e.currentTarget.style.borderColor = '#1c3823';
                  e.currentTarget.style.color = '#88a08d';
                }
              }}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
