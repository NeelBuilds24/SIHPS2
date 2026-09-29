import React from 'react';
import { X, CheckCircle, AlertTriangle, ShieldAlert, Cpu, GitMerge } from 'lucide-react';
import { Alert } from '../types';

interface AlertDrawerProps {
  alert: Alert | null;
  onClose: () => void;
}

export const AlertDrawer: React.FC<AlertDrawerProps> = ({ alert, onClose }) => {
  if (!alert) return null;

  const severityColor = {
    CRITICAL: 'bg-red-950/80 text-red-400 border-red-500/50',
    HIGH: 'bg-orange-950/80 text-orange-400 border-orange-500/50',
    MEDIUM: 'bg-yellow-950/80 text-yellow-400 border-yellow-500/50',
    LOW: 'bg-emerald-950/80 text-emerald-400 border-emerald-500/50',
  }[alert.severity] || 'bg-slate-800 text-slate-300 border-slate-700';

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm z-50 flex justify-end transition-opacity">
      <div className="w-full max-w-2xl bg-surface border-l border-border h-full overflow-y-auto p-6 flex flex-col justify-between shadow-2xl">
        <div>
          {/* Header */}
          <div className="flex items-center justify-between border-b border-border pb-4 mb-6">
            <div className="flex items-center gap-3">
              <div className="p-2.5 bg-red-950/60 border border-red-500/40 rounded-lg text-red-400">
                <ShieldAlert className="w-6 h-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs font-bold text-slate-400">{alert.alert_id}</span>
                  <span className={`px-2 py-0.5 text-xs font-bold rounded border ${severityColor}`}>
                    {alert.severity}
                  </span>
                </div>
                <h2 className="text-xl font-bold text-slate-100 font-mono tracking-wide mt-0.5">
                  {alert.threat}
                </h2>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded-lg transition"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          {/* Key Metrics Grid */}
          <div className="grid grid-cols-3 gap-3 mb-6">
            <div className="p-3 bg-slate-900 border border-border rounded-lg text-center">
              <div className="text-xs text-slate-400">ML Confidence</div>
              <div className="text-lg font-bold text-cyan-400 font-mono mt-1">
                {(alert.confidence * 100).toFixed(1)}%
              </div>
            </div>
            <div className="p-3 bg-slate-900 border border-border rounded-lg text-center">
              <div className="text-xs text-slate-400">Anomaly Score</div>
              <div className="text-lg font-bold text-amber-400 font-mono mt-1">
                {alert.anomaly_score.toFixed(2)}
              </div>
            </div>
            <div className="p-3 bg-slate-900 border border-border rounded-lg text-center">
              <div className="text-xs text-slate-400">Risk Score</div>
              <div className="text-lg font-bold text-red-400 font-mono mt-1">
                {alert.risk_score.toFixed(0)} <span className="text-xs text-slate-500">/ 100</span>
              </div>
            </div>
          </div>

          {/* Flow Parameters */}
          <div className="p-4 bg-slate-950/60 border border-border rounded-lg mb-6 space-y-2 text-xs font-mono">
            <div className="flex justify-between">
              <span className="text-slate-400">Source Endpoint:</span>
              <span className="text-cyan-300 font-bold">{alert.src_ip} {alert.src_port ? `:${alert.src_port}` : ''}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Destination Endpoint:</span>
              <span className="text-cyan-300 font-bold">{alert.dst_ip} {alert.dst_port ? `:${alert.dst_port}` : ''}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Protocol:</span>
              <span className="text-purple-300 font-bold">{alert.protocol}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-slate-400">Correlated Attack Chain:</span>
              <span className="text-amber-300 font-bold flex items-center gap-1">
                <GitMerge className="w-3.5 h-3.5" /> {alert.attack_chain_id || 'CHAIN-NONE'}
              </span>
            </div>
          </div>

          {/* Evidence List */}
          <div className="mb-6">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wide font-mono mb-3 flex items-center gap-2">
              <CheckCircle className="w-4 h-4 text-emerald-400" /> WHY WAS THIS DETECTED? (Supporting Evidence)
            </h3>
            <div className="space-y-2">
              {alert.evidence?.evidence && alert.evidence.evidence.length > 0 ? (
                alert.evidence.evidence.map((item, idx) => (
                  <div key={idx} className="p-3 bg-emerald-950/20 border border-emerald-500/30 rounded-lg text-xs text-emerald-300 flex items-start gap-2">
                    <span className="text-emerald-400 font-bold">✓</span>
                    <span>{item}</span>
                  </div>
                ))
              ) : (
                <div className="p-3 bg-slate-900 border border-border rounded-lg text-xs text-slate-400">
                  Flow parameters closely align with learned malicious statistical profile.
                </div>
              )}
            </div>
          </div>

          {/* Model Breakdown */}
          <div className="mb-6">
            <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wide font-mono mb-3 flex items-center gap-2">
              <Cpu className="w-4 h-4 text-cyan-400" /> Model Pipeline Breakdown
            </h3>
            <div className="grid grid-cols-2 gap-3 text-xs font-mono">
              <div className="p-3 bg-slate-900 border border-border rounded-lg">
                <div className="text-slate-400">Primary Classifier</div>
                <div className="font-bold text-slate-200 mt-1">XGBoost (Supervised)</div>
              </div>
              <div className="p-3 bg-slate-900 border border-border rounded-lg">
                <div className="text-slate-400">Anomaly Engine</div>
                <div className="font-bold text-slate-200 mt-1">Isolation Forest</div>
              </div>
            </div>
          </div>

          {/* Raw Metadata JSON */}
          {alert.raw_flow && (
            <div>
              <h3 className="text-xs font-bold text-slate-400 uppercase tracking-wide font-mono mb-2">
                Raw Passive Flow Metadata
              </h3>
              <pre className="p-3 bg-slate-950 border border-border rounded-lg text-[11px] font-mono text-cyan-300/80 overflow-x-auto max-h-40">
                {JSON.stringify(alert.raw_flow, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer Close Button */}
        <div className="pt-4 border-t border-border mt-6 flex justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 bg-slate-800 hover:bg-slate-700 text-slate-200 text-xs font-semibold rounded-lg transition"
          >
            Close Inspector
          </button>
        </div>
      </div>
    </div>
  );
};
