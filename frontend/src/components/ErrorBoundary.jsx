import React from 'react';

export default class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { error: null };
  }

  static getDerivedStateFromError(error) {
    return { error };
  }

  componentDidCatch(error, info) {
    // eslint-disable-next-line no-console
    console.error('PALANTIR UI crashed:', error, info);
  }

  render() {
    if (!this.state.error) return this.props.children;
    return (
      <div style={{ padding: 24 }}>
        <div className="box hot" style={{ maxWidth: 640, margin: '10vh auto' }}>
          <div className="box-title"><span className="t-edge">┐</span><span className="t-chip"><span className="t-name tone-red">crash</span></span><span className="t-edge">┌</span><span className="t-line" /></div>
          <pre className="pre">{String((this.state.error && this.state.error.stack) || this.state.error)}</pre>
          <button className="btn primary" onClick={() => window.location.reload()}>reload</button>
        </div>
      </div>
    );
  }
}
