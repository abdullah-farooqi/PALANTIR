import { CheckCircle2, AlertOctagon, X } from 'lucide-react';

export default function AnalysisToast({ toasts, onDismiss }) {
  if (!toasts || toasts.length === 0) return null;

  return (
    <div
      style={{
        position: 'fixed',
        bottom: 24,
        right: 24,
        zIndex: 2000,
        display: 'flex',
        flexDirection: 'column',
        gap: 10,
        width: 'min(100%, 360px)',
      }}
    >
      {toasts.map((toast) => {
        const isError = toast.type === 'error';
        return (
          <div
            key={toast.id}
            role="alert"
            style={{
              background: '#14171B',
              border: isError ? '1px solid #93000A' : '1px solid #434933',
              borderRadius: 8,
              boxShadow: '0 12px 32px rgba(0,0,0,0.5)',
              padding: 12,
              display: 'flex',
              alignItems: 'flex-start',
              justifyContent: 'space-between',
              gap: 12,
              fontFamily: "'Space Grotesk', sans-serif",
              color: '#E3E2E5',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
              {isError ? (
                <AlertOctagon size={18} style={{ color: '#E5484D', flexShrink: 0, marginTop: 2 }} />
              ) : (
                <CheckCircle2 size={18} style={{ color: '#C6FF00', flexShrink: 0, marginTop: 2 }} />
              )}
              <div style={{ display: 'flex', flexDirection: 'column' }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: isError ? '#FFB4AB' : '#FFFFFF' }}>
                  {toast.title}
                </span>
                <span style={{ fontSize: 11, color: '#BFC7D5', fontFamily: "'JetBrains Mono', monospace", marginTop: 2 }}>
                  {toast.message}
                </span>
              </div>
            </div>

            <button
              type="button"
              onClick={() => onDismiss(toast.id)}
              style={{
                background: 'transparent',
                border: 0,
                color: '#8B93A0',
                cursor: 'pointer',
                padding: 2,
              }}
              aria-label="Dismiss notification"
            >
              <X size={14} />
            </button>
          </div>
        );
      })}
    </div>
  );
}
