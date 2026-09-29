import React from 'react';
import { ShieldCheck, Eye, Lock } from 'lucide-react';

export const Header: React.FC = () => {
  return (
    <header className="h-16 border-b border-border bg-surface/80 backdrop-blur-md px-6 flex items-center justify-between sticky top-0 z-20">
      <div className="flex items-center gap-4">
        <div>
          <h1 className="text-base font-bold text-slate-100 tracking-wide font-mono flex items-center gap-2">
            SENTINEL<span className="text-cyan-400">GRAPH</span>
            <span className="text-xs font-normal text-slate-400 font-sans">| Passive Security Intelligence</span>
          </h1>
          <p className="text-xs text-slate-400 hidden sm:block">
            Detect the threat. Understand its evolution. Forecast what may come next.
          </p>
        </div>
      </div>

      <div className="flex items-center gap-4">
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 bg-cyan-950/40 border border-cyan-500/30 rounded-full text-xs font-medium text-cyan-300">
          <Lock className="w-3.5 h-3.5 text-cyan-400" />
          <span>PASSIVE ONE-WAY LINK</span>
          <span className="text-slate-500">•</span>
          <span className="text-slate-300">ZERO RETURN PATH</span>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-950/40 border border-emerald-500/30 rounded-full text-xs font-semibold text-emerald-400">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span>LIVE</span>
        </div>
      </div>
    </header>
  );
};
