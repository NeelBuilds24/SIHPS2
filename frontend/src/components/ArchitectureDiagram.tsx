import React from 'react';
import { ArrowRight, Shield, Database, Cpu, LayoutDashboard, Ban } from 'lucide-react';

export const ArchitectureDiagram: React.FC = () => {
  return (
    <div className="soc-card p-5 border border-cyan-500/20 bg-gradient-to-r from-slate-900/90 via-slate-900/60 to-slate-900/90 mb-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-cyan-400" />
          <h3 className="text-sm font-bold text-slate-200 tracking-wide uppercase font-mono">
            Strict Unidirectional Passive Ingestion Architecture
          </h3>
        </div>
        <span className="px-2.5 py-1 bg-red-950/60 border border-red-500/40 text-red-400 text-xs font-semibold rounded flex items-center gap-1.5">
          <Ban className="w-3.5 h-3.5" /> ZERO RETURN PATH (NO ACTIVE SCANNING)
        </span>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-5 gap-3 items-center text-center">
        {/* Step 1 */}
        <div className="p-3 bg-slate-950/80 border border-slate-700/50 rounded-lg">
          <div className="text-xs font-semibold text-slate-400 mb-1">MONITORED LINK</div>
          <div className="text-sm font-bold text-slate-100 font-mono">PRODUCTION NETWORK</div>
          <div className="text-[10px] text-slate-500 mt-1">Mirrored IP Traffic</div>
        </div>

        <div className="hidden md:flex flex-col items-center text-cyan-400">
          <span className="text-[10px] font-mono font-bold text-cyan-400 mb-1">ONE-WAY ONLY</span>
          <ArrowRight className="w-6 h-6 animate-pulse" />
        </div>

        {/* Step 2 */}
        <div className="p-3 bg-cyan-950/30 border border-cyan-500/40 rounded-lg">
          <div className="text-xs font-semibold text-cyan-400 mb-1">HARDWARE DIODE</div>
          <div className="text-sm font-bold text-cyan-200 font-mono">PASSIVE SENSOR</div>
          <div className="text-[10px] text-cyan-400/80 mt-1">Data Diode Enforced</div>
        </div>

        <div className="hidden md:flex flex-col items-center text-cyan-400">
          <span className="text-[10px] font-mono font-bold text-cyan-400 mb-1">ISOLATED ENCLAVE</span>
          <ArrowRight className="w-6 h-6 animate-pulse" />
        </div>

        {/* Step 3 */}
        <div className="p-3 bg-purple-950/30 border border-purple-500/40 rounded-lg">
          <div className="text-xs font-semibold text-purple-400 mb-1">AI/ML ENGINE</div>
          <div className="text-sm font-bold text-purple-200 font-mono">SENTINELGRAPH</div>
          <div className="text-[10px] text-purple-400/80 mt-1">XGBoost & Isolation Forest</div>
        </div>
      </div>
    </div>
  );
};
