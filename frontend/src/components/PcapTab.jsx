import React, { useState, useMemo, useCallback } from 'react';

// MOCK FORENSIC DATA: Admissible session reassemblies
const RECONSTRUCTED_SESSIONS = [
  { id: 101, proto: 'TLS 1.3', src: '10.0.1.5:54210', dst: '104.244.42.1:443', time: '08:14:01.042', packets: 1204, size: '1.2 MB', state: 'Clean Stream' },
  { id: 102, proto: 'DNS', src: '10.0.1.8:53211', dst: '1.1.1.1:53', time: '08:14:02.140', packets: 4, size: '512 B', state: 'Clean Query' },
  { id: 104, proto: 'HTTP', src: '10.0.1.4:49811', dst: '198.51.100.42:8080', time: '08:14:03.220', packets: 48, size: '84.2 KB', state: 'YARA Signature Match' },
  { id: 105, proto: 'SMB2', src: '10.0.1.4:49812', dst: '10.0.1.2:445', time: '08:14:04.004', packets: 512, size: '4.8 MB', state: 'Suspicious Relay' },
  { id: 106, proto: 'ICMP', src: '10.0.1.4:0', dst: '192.168.1.1:0', time: '08:14:04.991', packets: 8, size: '640 B', state: 'Echo Infiltration' },
];

export default function PcapTab({ onToast }) {
  const [selectedFlowId, setSelectedFlowId] = useState(104);
  const [isExporting, setIsExporting] = useState(false);
  const [exportComplete, setExportComplete] = useState(false);
  const [uploadProgress, setUploadProgress] = useState(100);

  const selectedFlow = useMemo(() => {
    return RECONSTRUCTED_SESSIONS.find((s) => s.id === selectedFlowId) || RECONSTRUCTED_SESSIONS[2];
  }, [selectedFlowId]);

  const handleExport = useCallback(() => {
    setIsExporting(true);
    setTimeout(() => {
      setIsExporting(false);
      setExportComplete(true);
      if (onToast) onToast('Forensic bundle packaged with SHA-256 manifest: apt29_evidence.zip');
      setTimeout(() => setExportComplete(false), 5000);
    }, 1200);
  }, [onToast]);

  return (
    <div className="flex flex-col gap-4">
      {/* Capture File Banner */}
      <section className="bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-wrap items-center justify-between gap-4">
        <div>
          <span className="font-mono text-xs text-[#656C77] uppercase tracking-wider">
            Target Packet Capture Ingestion
          </span>
          <h1 className="font-mono font-bold text-sm text-[#E8EAED] mt-0.5">
            incident-2026-11-10_apt29.pcap (1.42 GB)
          </h1>
          <span className="font-mono text-xs text-[#8B93A0] mt-1 inline-block">
            SHA-256: 4a2d88c9f0b1a37c9281e4b9... | Interface: eth0 (Mirror Port)
          </span>
        </div>

        <div className="flex items-center gap-3">
          {/* LOUD LIME: Primary Action button on this screen */}
          <button
            onClick={handleExport}
            disabled={isExporting}
            className="px-4 py-2 bg-[#C6FF00] hover:bg-[#D8FF4D] active:bg-[#A8DB00] text-[#0A0B0D] font-mono font-bold text-xs rounded-[4px] transition-colors focus:outline-none shadow-[0_0_12px_rgba(198,255,0,0.25)]"
          >
            {isExporting ? 'Packaging Hash Manifest...' : exportComplete ? '✔ Forensic Zip Exported' : 'Export Admissible Bundle'}
          </button>
        </div>
      </section>

      {/* Reassembly Progress Gauge */}
      <section className="bg-[#14171B] border border-[#262B32] p-4 rounded-[4px]">
        <div className="flex justify-between items-center mb-2 font-mono text-xs">
          <span className="font-sans font-semibold text-xs uppercase text-[#E8EAED]">
            Stream Carving & Protocol Extraction Progress
          </span>
          <span className="text-[#E8EAED]">
            {uploadProgress}% Carved (4,129 Flows, 18 Extracted Files)
          </span>
        </div>
        <div
          className="w-full h-2 bg-[#0A0B0D] border border-[#262B32] rounded-[2px] overflow-hidden"
          role="progressbar"
          aria-valuenow={uploadProgress}
          aria-valuemin={0}
          aria-valuemax={100}
          aria-label="PCAP reassembly progress"
        >
          <div
            className="h-full bg-[#8B93A0] transition-all duration-300"
            style={{ width: `${uploadProgress}%` }}
          />
        </div>
      </section>

      {/* Main Forensic Grid: Flow List vs. Detailed Evidence Drawer */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left: Reconstructed Session Table (7 cols) */}
        <section className="lg:col-span-7 bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-col">
          <div className="border-b border-[#1D2126] pb-3 mb-2 flex justify-between items-center">
            <h2 className="font-sans font-semibold text-xs tracking-wider uppercase text-[#E8EAED]">
              Reconstructed Forensic Flow Sessions
            </h2>
            <span className="font-mono text-xs text-[#656C77]">Click row to inspect hex payload</span>
          </div>

          <div className="overflow-x-auto">
            <table className="w-full text-left font-mono text-xs border-collapse" role="table">
              <thead>
                <tr className="border-b border-[#262B32] text-[#8B93A0]">
                  <th scope="col" className="py-2 px-2.5">ID</th>
                  <th scope="col" className="py-2 px-2.5">PROTO</th>
                  <th scope="col" className="py-2 px-2.5">SOCKET PATH</th>
                  <th scope="col" className="py-2 px-2.5">TIMESTAMP</th>
                  <th scope="col" className="py-2 px-2.5 text-right">SIZE</th>
                  <th scope="col" className="py-2 px-2.5">VERDICT</th>
                </tr>
              </thead>
              <tbody>
                {RECONSTRUCTED_SESSIONS.map((sess) => {
                  const isSelected = sess.id === selectedFlowId;
                  const isYara = sess.state.includes('YARA');
                  const isRelay = sess.state.includes('Relay');
                  return (
                    <tr
                      key={sess.id}
                      onClick={() => setSelectedFlowId(sess.id)}
                      onKeyDown={(e) => (e.key === 'Enter' || e.key === ' ') && setSelectedFlowId(sess.id)}
                      tabIndex={0}
                      role="row"
                      className={`border-b border-[#1D2126] cursor-pointer focus:outline-none transition-colors ${
                        isSelected
                          ? 'bg-[#1B1F24] border-l-2 border-l-[#C6FF00] text-[#E8EAED]'
                          : 'hover:bg-[#1B1F24] text-[#8B93A0]'
                      }`}
                    >
                      {/* LOUD LIME: Selected row id spotlight */}
                      <td className={`py-2.5 px-2.5 font-bold ${isSelected ? 'text-[#C6FF00]' : 'text-[#E8EAED]'}`}>
                        #{sess.id}
                      </td>
                      <td className="py-2.5 px-2.5">{sess.proto}</td>
                      <td className="py-2.5 px-2.5 font-sans text-xs">{sess.src} → {sess.dst}</td>
                      <td className="py-2.5 px-2.5 text-[#656C77]">{sess.time}</td>
                      <td className="py-2.5 px-2.5 text-right text-[#E8EAED]">{sess.size}</td>
                      <td className="py-2.5 px-2.5">
                        {isYara && (
                          <span className="text-[#FFA4A7] font-bold">✖ {sess.state}</span>
                        )}
                        {isRelay && (
                          <span className="text-[#FFD485] font-bold">▲ {sess.state}</span>
                        )}
                        {!isYara && !isRelay && (
                          <span className="text-[#656C77]">{sess.state}</span>
                        )}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </section>

        {/* Right: Forensic Artifact Evidence Drawer (5 cols) */}
        <section className="lg:col-span-5 bg-[#14171B] border border-[#262B32] p-4 rounded-[4px] flex flex-col gap-3">
          <div className="border-b border-[#1D2126] pb-3 flex justify-between items-center">
            <h2 className="font-sans font-semibold text-xs tracking-wider uppercase text-[#E8EAED]">
              Carved Evidence (Session #{selectedFlow.id})
            </h2>
            <span className="font-mono text-xs text-[#8B93A0]">Proto: {selectedFlow.proto}</span>
          </div>

          {/* Reconstructed File Hex & Metadata */}
          <div className="bg-[#0A0B0D] border border-[#262B32] p-3 rounded-[4px] flex flex-col gap-2 font-mono text-xs">
            <div className="flex justify-between text-[#8B93A0] border-b border-[#1D2126] pb-1">
              <span>SHA-256 HASH</span>
              <span className="text-[#E8EAED] truncate max-w-[200px]" title="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855">
                e3b0c44298fc1c149afbf...
              </span>
            </div>
            <div className="flex justify-between text-[#8B93A0] border-b border-[#1D2126] pb-1">
              <span>RECOVERED MIME</span>
              <span className="text-[#E8EAED]">application/x-dosexec (PE32 executable)</span>
            </div>
            <div className="flex justify-between text-[#8B93A0]">
              <span>CARVED LENGTH</span>
              <span className="text-[#E8EAED]">{selectedFlow.size} (48 Packets)</span>
            </div>
          </div>

          {/* YARA & MITRE ATT&CK Signatures */}
          <div className="p-3 bg-[rgba(229,72,77,0.12)] border border-[rgba(229,72,77,0.40)] rounded-[4px] flex flex-col gap-1.5 font-mono text-xs">
            <div className="flex items-center justify-between text-[#FFA4A7] font-bold">
              <span>✖ YARA SIGNATURE TRIGGERED</span>
              <span>CONFIDENCE: 10/10</span>
            </div>
            <span className="text-[#E8EAED] font-sans text-xs">
              Rule: APT_CobaltStrike_Malleable_C2_Beacon
            </span>
            <div className="mt-1 pt-1 border-t border-[rgba(229,72,77,0.30)] flex justify-between text-[11px] text-[#8B93A0]">
              <span>MITRE ATT&CK: T1059.001</span>
              <span>CVSS v3.1: 9.8 (CRITICAL)</span>
            </div>
          </div>

          {/* Forensic Hex Stream Dump */}
          <div className="flex flex-col gap-1">
            <span className="font-mono text-xs text-[#656C77] uppercase">
              Stream Packet Hex Header (Offset 0x00000000)
            </span>
            <pre className="bg-[#0A0B0D] border border-[#262B32] p-3 rounded-[4px] font-mono text-[11px] text-[#8B93A0] overflow-x-auto leading-relaxed">
{`00000000  4d 5a 90 00 03 00 00 00  04 00 00 00 ff ff 00 00  |MZ..............|
00000010  b8 00 00 00 00 00 00 00  40 00 00 00 00 00 00 00  |........@.......|
00000020  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00  |................|
00000030  00 00 00 00 00 00 00 00  00 00 00 00 80 00 00 00  |................|`}
            </pre>
          </div>
        </section>
      </div>
    </div>
  );
}
