import { useEffect, useRef, useState } from 'react';
import { api } from '../api';
import { Spinner } from './ui';

const formatUrl = (ip, port) => {
  if (!ip) return '';
  const clean = ip.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
  return `http://${clean}:${port}`;
};

export default function AddNodeModal({ onClose, onCreated }) {
  const [hostname, setHostname] = useState('');
  const [hostIp, setHostIp] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState('');
  const firstInput = useRef(null);

  useEffect(() => {
    if (firstInput.current) firstInput.current.focus();
  }, []);

  useEffect(() => {
    const onKey = (e) => e.key === 'Escape' && onClose();
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [onClose]);

  async function submit(e) {
    e.preventDefault();
    setError('');

    const cleanIp = hostIp.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '');
    const payload = {
      hostname: hostname.trim(),
      collector_url: formatUrl(cleanIp, 20000),
      os_type: 'linux',
    };

    setSubmitting(true);
    try {
      onCreated(await api.registerNode(payload));
    } catch (err) {
      setError(err.message);
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="modal-back" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <form
        className="box modal hot"
        onSubmit={submit}
        role="dialog"
        aria-modal="true"
        style={{
          maxWidth: '560px',
          padding: '24px 22px 18px',
          background: '#070c08',
          borderColor: '#193822',
          borderRadius: '14px',
          boxShadow: '0 0 35px rgba(20, 60, 30, 0.4)'
        }}
      >
        <div className="box-title" style={{ fontSize: '14px' }}>
          <span className="t-edge">┐</span>
          <span className="t-chip"><span className="t-name" style={{ fontSize: '15px', color: '#39e569' }}>Register Host Node</span></span>
          <span className="t-edge">┌</span>
          <span className="t-line" />
          <span className="t-right" style={{ fontSize: '12px', color: '#728c78' }}>esc to close</span>
        </div>

        {error && <div className="banner" style={{ marginBottom: 14, fontSize: '13.5px' }}>{error}</div>}

        <div style={{ display: 'grid', gap: 18, marginTop: 6 }}>
          <div>
            <label className="lbl" htmlFor="n-host" style={{ fontSize: '14px', fontWeight: '600', color: '#a3c4aa', marginBottom: '6px' }}>
              Hostname / Label
            </label>
            <input
              id="n-host"
              ref={firstInput}
              className="in"
              style={{ width: '100%', padding: '10px 14px', fontSize: '14.5px', borderRadius: '8px', background: '#000', borderColor: '#1c4026', color: '#fff' }}
              required
              pattern="[a-zA-Z0-9_.\-]+"
              placeholder="e.g. prod-server-01"
              value={hostname}
              onChange={(e) => setHostname(e.target.value)}
            />
          </div>

          <div>
            <label className="lbl" htmlFor="n-ip" style={{ fontSize: '14px', fontWeight: '600', color: '#a3c4aa', marginBottom: '6px' }}>
              Target Host IP Address
            </label>
            <input
              id="n-ip"
              className="in"
              style={{ width: '100%', padding: '10px 14px', fontSize: '14.5px', borderRadius: '8px', background: '#000', borderColor: '#1c4026', color: '#fff' }}
              required
              placeholder="e.g. 192.168.1.50 or 172.17.0.1"
              value={hostIp}
              onChange={(e) => setHostIp(e.target.value)}
            />
          </div>

          <div className="row" style={{ justifyContent: 'space-between', marginTop: 8, alignItems: 'center' }}>
            <button
              type="button"
              className="btn"
              onClick={onClose}
              style={{ padding: '8px 20px', fontSize: '14px', fontWeight: '600', borderRadius: '8px', borderColor: '#234d2c', color: '#8da693' }}
            >
              Cancel
            </button>
            <button
              type="submit"
              className="btn primary"
              disabled={submitting}
              style={{ padding: '8px 24px', fontSize: '14px', fontWeight: '800', borderRadius: '8px', background: '#39e569', color: '#000', boxShadow: '0 0 15px rgba(57, 229, 105, 0.3)' }}
            >
              {submitting ? <><Spinner /> Connecting…</> : 'Register Host'}
            </button>
          </div>
        </div>
      </form>
    </div>
  );
}
