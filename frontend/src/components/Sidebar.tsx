import React from 'react';
import {
  LayoutDashboard,
  Activity,
  GitMerge,
  Share2,
  ShieldAlert,
  TrendingUp,
  Sliders,
  Link2,
  Target,
  Settings,
  Shield,
  Lock
} from 'lucide-react';

export type PageId =
  | 'overview'
  | 'live-detection'
  | 'attack-chains'
  | 'attack-graph'
  | 'threat-intel'
  | 'forecast'
  | 'baseline'
  | 'audit-trail'
  | 'model-performance'
  | 'settings';

interface SidebarProps {
  currentPage: PageId;
  onSelectPage: (page: PageId) => void;
}

const navItems: Array<{ id: PageId; label: string; icon: React.FC<{ className?: string }> }> = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'live-detection', label: 'Live Detection', icon: Activity },
  { id: 'attack-chains', label: 'Attack Chains', icon: GitMerge },
  { id: 'attack-graph', label: 'Attack Graph', icon: Share2 },
  { id: 'threat-intel', label: 'Threat Intelligence', icon: ShieldAlert },
  { id: 'forecast', label: 'Forecast', icon: TrendingUp },
  { id: 'baseline', label: 'Baseline', icon: Sliders },
  { id: 'audit-trail', label: 'Audit Trail', icon: Link2 },
  { id: 'model-performance', label: 'Model Performance', icon: Target },
  { id: 'settings', label: 'Settings & Upload', icon: Settings },
];

export const Sidebar: React.FC<SidebarProps> = ({ currentPage, onSelectPage }) => {
  return (
    <aside className="w-64 bg-surface border-r border-border flex flex-col justify-between h-screen sticky top-0 select-none z-30">
      {/* Top Logo */}
      <div>
        <div className="p-5 border-b border-border flex items-center gap-3">
          <div className="p-2 bg-cyan-950/60 border border-cyan-500/30 rounded-lg text-cyan-400">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <h1 className="font-bold text-lg tracking-wider text-slate-100 font-mono">
              SENTINEL<span className="text-cyan-400">GRAPH</span>
            </h1>
            <p className="text-[11px] text-slate-400 font-medium">NTRO PS 26145 Enclave</p>
          </div>
        </div>

        {/* Navigation Items */}
        <nav className="p-3 space-y-1">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = currentPage === item.id;
            return (
              <button
                key={item.id}
                onClick={() => onSelectPage(item.id)}
                className={`w-full flex items-center gap-3 px-3.5 py-2.5 rounded-lg text-sm font-medium transition-all ${
                  isActive
                    ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/30 shadow-[0_0_12px_rgba(0,240,255,0.15)]'
                    : 'text-slate-400 hover:text-slate-200 hover:bg-slate-800/50'
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? 'text-cyan-400' : 'text-slate-400'}`} />
                <span>{item.label}</span>
              </button>
            );
          })}
        </nav>
      </div>

      {/* Bottom Status Card */}
      <div className="p-4 border-t border-border bg-slate-950/40">
        <div className="p-3 bg-slate-900/80 border border-emerald-500/30 rounded-lg">
          <div className="flex items-center gap-2 mb-1.5">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
            </span>
            <span className="text-xs font-bold tracking-wide text-emerald-400">SYSTEM ONLINE</span>
          </div>
          <p className="text-[11px] text-slate-300 font-medium flex items-center gap-1">
            <Lock className="w-3 h-3 text-cyan-400" /> Passive Monitoring
          </p>
          <p className="text-[10px] text-slate-500 mt-0.5">One-Way Ingest (Data Diode)</p>
        </div>
      </div>
    </aside>
  );
};
