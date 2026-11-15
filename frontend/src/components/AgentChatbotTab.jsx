import { Database, LockKeyhole, MessageSquareText, Sparkles } from 'lucide-react';

export default function AgentChatbotTab() {
  return (
    <div className="fleet-overview copilot-preview">
      <section className="fleet-page-heading">
        <div>
          <div className="fleet-eyebrow"><span>ASSISTED ANALYSIS</span><span className="fleet-heading-divider" /><span>PREVIEW</span></div>
          <h1>Copilot preview</h1>
          <p>Review the planned assistant workspace and its connection requirements.</p>
        </div>
        <span className="copilot-preview-badge"><Sparkles size={14} />PREVIEW</span>
      </section>

      <section className="copilot-notice" role="status">
        <div className="copilot-notice-icon"><MessageSquareText size={19} /></div>
        <div>
          <h2>No Copilot service is connected</h2>
          <p>This project does not currently expose an assistant API. The preview has no live fleet context and cannot answer prompts or run actions.</p>
        </div>
      </section>

      <section className="copilot-status-grid" aria-label="Copilot connection status">
        <article className="copilot-status-card">
          <Database size={17} />
          <div><span>FLEET DATA ACCESS</span><strong>Not connected</strong><small>No assistant data source is configured.</small></div>
        </article>
        <article className="copilot-status-card">
          <LockKeyhole size={17} />
          <div><span>ACTION EXECUTION</span><strong>Disabled</strong><small>No action approval or execution service is configured.</small></div>
        </article>
      </section>

      <section className="copilot-empty-workspace">
        <Sparkles size={22} aria-hidden="true" />
        <h2>Assistant conversation</h2>
        <p>Conversation controls become available when a Copilot service is connected.</p>
        <button type="button" disabled aria-disabled="true">Prompt unavailable</button>
      </section>
    </div>
  );
}
