import React, { useEffect, useState } from 'react';
import { Link2, ShieldCheck, AlertOctagon, RotateCcw, CheckCircle2 } from 'lucide-react';
import { api } from '../services/api';
import { AuditResponse } from '../types';

export const AuditTrail: React.FC = () => {
  const [auditData, setAuditData] = useState<AuditResponse | null>(null);
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    fetchAuditLedger();
  }, []);

  const fetchAuditLedger = async () => {
    setLoading(true);
    try {
      const res = await api.getAuditLedger();
      setAuditData(res);
    } catch (err) {
      console.error('Error fetching audit ledger:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleVerify = async () => {
    fetchAuditLedger();
  };

  const handleSimulateTamper = async () => {
    try {
      await api.simulateTampering(1);
      fetchAuditLedger();
    } catch (err) {
      console.error('Error simulating tampering:', err);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 font-mono tracking-wide">
            Evidence Integrity Audit Ledger
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Permissioned SHA-256 cryptographic hash chain preserving alert evidence integrity
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={handleVerify}
            className="px-3.5 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition border border-slate-700 flex items-center gap-2"
          >
            <ShieldCheck className="w-4 h-4 text-cyan-400" /> Verify Chain
          </button>

          <button
            onClick={handleSimulateTamper}
            className="px-3.5 py-2 bg-red-950/80 hover:bg-red-900 text-red-300 text-xs font-bold rounded-lg transition border border-red-800 flex items-center gap-2"
          >
            <AlertOctagon className="w-4 h-4 text-red-400" /> Simulate Tampering
          </button>
        </div>
      </div>

      {/* Explanatory Notice */}
      <div className="p-4 bg-slate-900 border border-border rounded-lg text-xs text-slate-300 flex items-center gap-3">
        <Link2 className="w-5 h-5 flex-shrink-0 text-cyan-400" />
        <span>
          <strong>Audit Role Clarity:</strong> Blockchain hash-chaining is used strictly to preserve tamper-evident evidence integrity for security compliance. It does not perform detection or prediction.
        </span>
      </div>

      {/* Status Banner */}
      {auditData && (
        <div className={`p-4 rounded-lg border text-sm font-mono font-bold flex items-center justify-between ${
          auditData.is_valid
            ? 'bg-emerald-950/50 border-emerald-500/50 text-emerald-400'
            : 'bg-red-950/60 border-red-500/60 text-red-400 animate-pulse'
        }`}>
          <div className="flex items-center gap-3">
            {auditData.is_valid ? <CheckCircle2 className="w-5 h-5" /> : <AlertOctagon className="w-5 h-5" />}
            <span>{auditData.status}</span>
          </div>

          <div className="text-xs text-slate-300 font-normal">
            Blocks: <strong className="text-slate-100">{auditData.chain_length}</strong> | Latest Block: <strong className="text-cyan-300">#{auditData.chain_length - 1}</strong>
          </div>
        </div>
      )}

      {/* Hash Chain Block Explorer Table */}
      <div className="soc-card overflow-hidden">
        <div className="p-4 border-b border-border font-mono text-xs font-bold text-slate-200">
          Cryptographic Hash Chain Blocks ({auditData?.chain_length || 0})
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 uppercase border-b border-border">
              <tr>
                <th className="p-3">Block #</th>
                <th className="p-3">Timestamp</th>
                <th className="p-3">Alert ID</th>
                <th className="p-3">Chain ID</th>
                <th className="p-3">Evidence Hash</th>
                <th className="p-3">Previous Hash</th>
                <th className="p-3">Block Hash</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50 text-slate-200">
              {auditData?.blocks && auditData.blocks.length > 0 ? (
                auditData.blocks.map(block => (
                  <tr key={block.index} className="hover:bg-slate-800/60 transition">
                    <td className="p-3 font-bold text-cyan-400">#{block.index}</td>
                    <td className="p-3 text-slate-400">{block.timestamp}</td>
                    <td className="p-3 font-bold text-slate-200">{block.alert_id}</td>
                    <td className="p-3 text-purple-300">{block.attack_chain_id}</td>
                    <td className="p-3 font-mono text-[11px] text-amber-300/80 truncate max-w-[120px]">{block.evidence_hash}</td>
                    <td className="p-3 font-mono text-[11px] text-slate-500 truncate max-w-[120px]">{block.previous_hash}</td>
                    <td className="p-3 font-mono text-[11px] text-emerald-400 truncate max-w-[120px]">{block.hash}</td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={7} className="p-6 text-center text-slate-500">
                    No audit blocks generated yet.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};
