import React, { useEffect, useState } from 'react';
import { Sliders, ShieldCheck, AlertTriangle, TrendingUp } from 'lucide-react';
import { api } from '../services/api';
import { BaselineStats } from '../types';

export const AdaptiveBaseline: React.FC = () => {
  const [stats, setStats] = useState<BaselineStats | null>(null);
  const [simUdpRate, setSimUdpRate] = useState<number>(14800);

  useEffect(() => {
    fetchBaseline();
  }, []);

  const fetchBaseline = async () => {
    try {
      const res = await api.getBaseline();
      setStats(res);
    } catch (err) {
      console.error('Error fetching baseline:', err);
    }
  };

  const normalUdpRate = stats?.udp_pkt_rate_min || 1200;
  const deviationPct = ((simUdpRate - normalUdpRate) / normalUdpRate) * 100;
  const status = deviationPct >= 500 ? 'CRITICAL' : deviationPct >= 200 ? 'HIGH' : 'ELEVATED';

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 font-mono tracking-wide">
            Adaptive Behavioural Baseline
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Poisoning-resistant baseline engine learning normal environment dynamics exclusively from benign flows
          </p>
        </div>

        <div className="flex items-center gap-2 px-3 py-1.5 bg-emerald-950/40 border border-emerald-500/30 rounded-lg text-xs font-mono font-semibold text-emerald-400">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span>BASELINE STATUS: LEARNING</span>
        </div>
      </div>

      {/* Poisoning-resistance Notice */}
      <div className="p-4 bg-cyan-950/40 border border-cyan-500/40 rounded-lg flex items-center gap-3 text-xs text-cyan-300">
        <ShieldCheck className="w-5 h-5 flex-shrink-0 text-cyan-400" />
        <span>
          <strong>Poisoning Resistance Enforced:</strong> SentinelGraph automatically filters out malicious traffic from modifying dynamic baseline exponential moving averages (EMA).
        </span>
      </div>

      {/* Baseline Metric Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 font-mono">
        <div className="soc-card p-4 text-center border-l-4 border-l-cyan-500">
          <div className="text-xs text-slate-400">NORMAL PACKETS / SEC</div>
          <div className="text-2xl font-bold text-slate-100 mt-1">
            {stats?.packets_per_sec.toFixed(1) || '15.0'}
          </div>
        </div>

        <div className="soc-card p-4 text-center border-l-4 border-l-purple-500">
          <div className="text-xs text-slate-400">NORMAL BYTES / SEC</div>
          <div className="text-2xl font-bold text-purple-400 mt-1">
            {stats ? (stats.bytes_per_sec / 1024).toFixed(1) : '8.5'} <span className="text-xs font-normal">KB/s</span>
          </div>
        </div>

        <div className="soc-card p-4 text-center border-l-4 border-l-amber-500">
          <div className="text-xs text-slate-400">NORMAL UDP RATE</div>
          <div className="text-2xl font-bold text-amber-400 mt-1">
            {normalUdpRate.toLocaleString()} <span className="text-xs font-normal">pkts/min</span>
          </div>
        </div>

        <div className="soc-card p-4 text-center border-l-4 border-l-emerald-500">
          <div className="text-xs text-slate-400">LEARNED SAMPLES</div>
          <div className="text-2xl font-bold text-emerald-400 mt-1">
            {stats?.sample_count || 100}
          </div>
        </div>
      </div>

      {/* Interactive Deviation Simulator */}
      <div className="soc-card p-6 space-y-6">
        <h3 className="text-sm font-bold text-slate-200 font-mono uppercase tracking-wide flex items-center gap-2 border-b border-border pb-3">
          <Sliders className="w-4 h-4 text-cyan-400" /> Interactive Traffic Deviation Simulator
        </h3>

        <div className="space-y-4">
          <div className="flex items-center justify-between text-xs font-mono">
            <span className="text-slate-400">Simulate Incoming UDP Packet Rate:</span>
            <span className="font-bold text-cyan-400 text-sm">{simUdpRate.toLocaleString()} packets/min</span>
          </div>

          <input
            type="range"
            min={1000}
            max={30000}
            step={200}
            value={simUdpRate}
            onChange={e => setSimUdpRate(Number(e.target.value))}
            className="w-full h-2 bg-slate-900 rounded-lg appearance-none cursor-pointer accent-cyan-400"
          />
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 font-mono text-center pt-2">
          <div className="p-4 bg-slate-900 border border-border rounded-lg">
            <div className="text-xs text-slate-400">Baseline Normal UDP Rate</div>
            <div className="text-lg font-bold text-slate-200 mt-1">{normalUdpRate.toLocaleString()} pkts/min</div>
          </div>

          <div className="p-4 bg-slate-900 border border-border rounded-lg">
            <div className="text-xs text-slate-400">Observed Incoming Rate</div>
            <div className="text-lg font-bold text-cyan-400 mt-1">{simUdpRate.toLocaleString()} pkts/min</div>
          </div>

          <div className="p-4 bg-slate-900 border border-border rounded-lg">
            <div className="text-xs text-slate-400">Baseline Deviation</div>
            <div className={`text-lg font-bold mt-1 ${deviationPct >= 500 ? 'text-red-400' : 'text-amber-400'}`}>
              +{deviationPct.toFixed(0)}% ({status})
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
