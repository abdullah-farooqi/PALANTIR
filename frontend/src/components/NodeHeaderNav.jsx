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
    <div className="node-header-nav">
      {/* Left: Back button + Hostname + IP */}
      <div className="node-header-identity">
        {onBack && (
          <button
            className="node-header-back"
            onClick={onBack}
            title="Return to Fleet Grid"
          >
            <svg viewBox="0 0 24 24" width="20" height="20" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
              <line x1="19" y1="12" x2="5" y2="12"></line>
              <polyline points="12 19 5 12 12 5"></polyline>
            </svg>
          </button>
        )}
        <span className="node-header-hostname">
          {node?.hostname || 'Host Details'}
        </span>
        {hostIp && (
          <span className="node-header-address">
            {hostIp}
          </span>
        )}
        {node?.reachability && <span className={`node-header-reachability ${node.reachability}`}>{node.reachability}</span>}
      </div>

      {/* Right: Quick Tab Navigation Buttons */}
      <div className="node-header-tabs" role="tablist" aria-label="Host screens">
        {TABS.map((tab) => {
          const isActive = currentView === tab.key;
          return (
            <button
              key={tab.key}
              onClick={() => onViewChange(tab.key)}
              className={`node-header-tab ${isActive ? 'active' : ''}`}
              role="tab"
              aria-selected={isActive}
            >
              {tab.label}
            </button>
          );
        })}
      </div>
    </div>
  );
}
