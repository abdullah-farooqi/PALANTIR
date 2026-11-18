import { useState } from 'react';
import { AlertTriangle, Check, Copy, Download, ShieldAlert, X } from 'lucide-react';
import { formatBytes } from '../../lib/format';

export default function ArtifactQuarantineModal({
  isOpen,
  onClose,
  artifact,
  downloadUrl,
  onDownloadStarted,
  onDownloadError,
}) {
  const [acknowledged, setAcknowledged] = useState(false);
  const [copiedSha, setCopiedSha] = useState(false);
  const [isDownloading, setIsDownloading] = useState(false);

  if (!isOpen || !artifact) return null;

  const sha256 = artifact.sha256 || '—';
  const md5 = artifact.md5 || '—';
  const fileName = artifact.fileName || artifact.metadata?.filename || `artifact_${artifact.id}.bin`;
  const sizeFormatted = artifact.size_bytes ? formatBytes(artifact.size_bytes) : '18.4 KB';
  const contentType = artifact.content_type || 'application/octet-stream';
  const sourceUri = artifact.source_uri || artifact.metadata?.uri || 'HTTP stream extraction';

  const handleCopySha = () => {
    navigator.clipboard.writeText(sha256);
    setCopiedSha(true);
    setTimeout(() => setCopiedSha(false), 2000);
  };

  const handleDownload = async () => {
    if (!acknowledged || isDownloading) return;
    setIsDownloading(true);

    try {
      const response = await fetch(downloadUrl, { credentials: 'include' });
      if (response.status === 410) {
        throw new Error('Cache expired from sandbox worker (TTL 24h)');
      }
      if (!response.ok) {
        throw new Error(`Download failed with status ${response.status}`);
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = fileName;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      a.remove();

      onDownloadStarted?.({ fileName, sizeFormatted });
      onClose();
    } catch (err) {
      onDownloadError?.(err.message || 'Artifact no longer available');
      onClose();
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <div
      className="analysis-confirm-backdrop"
      role="presentation"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget && !isDownloading) onClose();
      }}
      style={{
        position: 'fixed',
        inset: 0,
        zIndex: 1000,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        background: 'rgba(0, 0, 0, 0.78)',
        backdropFilter: 'blur(3px)',
      }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="artifact-modal-title"
        style={{
          width: 'min(100%, 540px)',
          background: '#14171B',
          border: '1px solid #262B32',
          borderRadius: 8,
          boxShadow: '0 20px 48px rgba(0,0,0,0.65)',
          padding: 24,
          display: 'flex',
          flexDirection: 'column',
          gap: 16,
          color: '#E3E2E5',
          fontFamily: "'Space Grotesk', sans-serif",
        }}
      >
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderBottom: '1px solid #262B32', paddingBottom: 14 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ width: 32, height: 32, borderRadius: 6, background: '#2C1517', display: 'flex', alignItems: 'center', justifyContent: 'center', border: '1px solid #57383A', color: '#E5484D' }}>
              <ShieldAlert size={18} />
            </div>
            <div>
              <div style={{ fontSize: 9, fontFamily: "'JetBrains Mono', monospace", color: '#E5484D', letterSpacing: '0.08em', textTransform: 'uppercase' }}>
                Hazard Artifact Quarantine · Frame 02
              </div>
              <h2 id="artifact-modal-title" style={{ margin: 0, fontSize: 16, fontWeight: 600, color: '#FFFFFF' }}>
                Download extracted artifact
              </h2>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            disabled={isDownloading}
            style={{ background: 'transparent', border: 0, color: '#8B93A0', cursor: 'pointer', padding: 4 }}
            aria-label="Close dialog"
          >
            <X size={18} />
          </button>
        </div>

        {/* Body */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
          {/* Quarantine Warning Banner */}
          <div
            style={{
              border: '1px solid #434933',
              background: '#0D0E10',
              borderRadius: 6,
              padding: 12,
              display: 'flex',
              alignItems: 'flex-start',
              gap: 10,
              fontSize: 12,
              lineHeight: 1.45,
            }}
          >
            <AlertTriangle size={18} style={{ color: '#E5484D', flexShrink: 0, marginTop: 1 }} />
            <div>
              <span style={{ fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.06em', display: 'block', marginBottom: 2, color: '#FFFFFF' }}>
                Quarantine Warning
              </span>
              This file was extracted from captured network traffic and may be malicious. Do not open it on a production machine or without sandbox isolation.
            </div>
          </div>

          {/* Artifact Details Grid */}
          <div
            style={{
              background: '#0D0E10',
              border: '1px solid #262B32',
              borderRadius: 6,
              padding: 12,
              display: 'flex',
              flexDirection: 'column',
              gap: 10,
              fontFamily: "'JetBrains Mono', monospace",
              fontSize: 11,
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1F2022', paddingBottom: 6 }}>
              <span style={{ color: '#8D9479', textTransform: 'uppercase', fontSize: 10 }}>File Name</span>
              <span style={{ color: '#FFFFFF', fontWeight: 600 }}>
                {fileName} <span style={{ color: '#8B93A0', fontWeight: 400, fontSize: 10 }}>({contentType} · {sizeFormatted})</span>
              </span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid #1F2022', paddingBottom: 6 }}>
              <span style={{ color: '#8D9479', textTransform: 'uppercase', fontSize: 10 }}>Source</span>
              <span style={{ color: '#BFC7D5', maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={sourceUri}>
                {sourceUri}
              </span>
            </div>

            {/* SHA-256 with copy button */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, borderBottom: '1px solid #1F2022', paddingBottom: 6 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <span style={{ color: '#8D9479', textTransform: 'uppercase', fontSize: 10 }}>SHA-256 Checksum</span>
                <button
                  type="button"
                  onClick={handleCopySha}
                  style={{
                    background: 'transparent',
                    border: 0,
                    color: '#C6FF00',
                    fontSize: 10,
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: 4,
                  }}
                >
                  {copiedSha ? <Check size={12} /> : <Copy size={12} />}
                  <span>{copiedSha ? 'COPIED' : 'COPY HASH'}</span>
                </button>
              </div>
              <div style={{ background: '#1F2022', padding: '6px 8px', borderRadius: 4, border: '1px solid #262B32', fontSize: 10, color: '#22D3EE', wordBreak: 'break-all', userSelect: 'all' }}>
                {sha256}
              </div>
            </div>

            {/* MD5 */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ color: '#8D9479', textTransform: 'uppercase', fontSize: 10 }}>MD5</span>
              <span style={{ color: '#BFC7D5', userSelect: 'all' }}>{md5}</span>
            </div>
          </div>

          {/* Mandatory Checkbox */}
          <label
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: 10,
              padding: '8px 10px',
              borderRadius: 6,
              background: '#1F2022',
              border: acknowledged ? '1px solid #C6FF00' : '1px solid #262B32',
              cursor: 'pointer',
              userSelect: 'none',
              fontSize: 12,
              lineHeight: 1.4,
            }}
          >
            <input
              type="checkbox"
              checked={acknowledged}
              onChange={(e) => setAcknowledged(e.target.checked)}
              style={{ marginTop: 2, accentColor: '#C6FF00', width: 16, height: 16, cursor: 'pointer' }}
            />
            <span style={{ color: '#FFFFFF' }}>
              I understand the risks and intend to inspect this artifact in an isolated analysis sandbox.
            </span>
          </label>
        </div>

        {/* Footer */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid #262B32', paddingTop: 16 }}>
          <span style={{ fontSize: 11, color: '#8D9479', display: 'flex', alignItems: 'center', gap: 6, fontFamily: "'JetBrains Mono', monospace" }}>
            <span style={{ width: 6, height: 6, borderRadius: '50%', background: '#C6FF00' }} />
            Isolation Verified
          </span>

          <div style={{ display: 'flex', gap: 10 }}>
            <button
              type="button"
              onClick={onClose}
              disabled={isDownloading}
              style={{
                padding: '8px 16px',
                borderRadius: 4,
                border: '1px solid #343537',
                background: '#1F2022',
                color: '#BFC7D5',
                cursor: 'pointer',
                fontSize: 12,
                fontFamily: "'Space Grotesk', sans-serif",
                fontWeight: 500,
              }}
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleDownload}
              disabled={!acknowledged || isDownloading}
              style={{
                padding: '8px 18px',
                borderRadius: 4,
                border: 'none',
                background: acknowledged ? '#C6FF00' : '#272B20',
                color: acknowledged ? '#151F00' : '#888D79',
                cursor: acknowledged ? (isDownloading ? 'wait' : 'pointer') : 'not-allowed',
                fontSize: 12,
                fontFamily: "'Space Grotesk', sans-serif",
                fontWeight: 700,
                display: 'flex',
                alignItems: 'center',
                gap: 6,
              }}
            >
              <Download size={15} />
              <span>{isDownloading ? 'Downloading…' : 'Download artifact'}</span>
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
