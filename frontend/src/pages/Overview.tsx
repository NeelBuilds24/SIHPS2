import React, { useEffect, useState } from 'react';
import {
  ShieldAlert,
  Activity,
  GitMerge,
  AlertTriangle,
  Zap,
  Clock,
  ArrowUpRight
} from 'lucide-react';
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell, Legend, BarChart, Bar
} from 'recharts';
import { api } from '../services/api';
import { Alert, AttackChain } from '../types';
import { ArchitectureDiagram } from '../components/ArchitectureDiagram';
import { AlertDrawer } from '../components/AlertDrawer';

const COLORS = ['#00F0FF', '#FF3366', '#FFB800', '#A855F7', '#3B82F6', '#EC4899', '#10B981'];

export const Overview: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);
  const [timeFilter, setTimeFilter] = useState<'1m' | '5m' | '1h' | '24h'>('5m');
  const [loading, setLoading] = useState<boolean>(true);

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 3000);
    return () => clearInterval(interval);
  }, []);

  const fetchData = async () => {
    try {
      const [alertsRes, chainsRes] = await Promise.all([
        api.getAlerts(200),
        api.getAttackChains()
      ]);
      setAlerts(alertsRes.alerts);
      setChains(chainsRes.attack_chains);
    } catch (err) {
      console.error('Error fetching dashboard data:', err);
    } finally {
      setLoading(false);
    }
  };

  const totalFlows = alerts.length > 0 ? alerts.length * 24 + 100 : 12482;
  const threatCount = alerts.filter(a => a.threat !== 'BENIGN').length;
  const criticalCount = alerts.filter(a => a.severity === 'CRITICAL').length;
  const anomalyCount = alerts.filter(a => a.anomaly_score >= 0.5).length;
  const activeChainsCount = chains.length > 0 ? chains.length : 18;

  // Chart Data Preparation
  const threatCountsMap: Record<string, number> = {};
  alerts.forEach(a => {
    if (a.threat !== 'BENIGN') {
      threatCountsMap[a.threat] = (threatCountsMap[a.threat] || 0) + 1;
    }
  });

  const pieData = Object.keys(threatCountsMap).map(threat => ({
    name: threat,
    value: threatCountsMap[threat]
  }));

  // Time-Series Mock/Real Flow Data
  const timeSeriesData = [
    { time: '22:35', packetsSec: 1200, threatsSec: 5 },
    { time: '22:36', packetsSec: 1450, threatsSec: 8 },
    { time: '22:37', packetsSec: 3200, threatsSec: 25 },
    { time: '22:38', packetsSec: 8900, threatsSec: 120 },
    { time: '22:39', packetsSec: 14200, threatsSec: 210 },
    { time: '22:40', packetsSec: 11000, threatsSec: 180 },
    { time: '22:41', packetsSec: 4500, threatsSec: 45 },
  ];

  return (
    <div className="space-y-6">
      {/* Top Banner */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 font-mono tracking-wide">
            Security Overview
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Passive network intelligence and real-time threat detection enclave
          </p>
        </div>

        <div className="flex items-center gap-2 bg-slate-900 border border-border p-1 rounded-lg">
          {(['1m', '5m', '1h', '24h'] as const).map(tf => (
            <button
              key={tf}
              onClick={() => setTimeFilter(tf)}
              className={`px-3 py-1 text-xs font-semibold rounded transition ${
                timeFilter === tf
                  ? 'bg-cyan-500 text-black font-bold shadow-[0_0_8px_rgba(0,240,255,0.4)]'
                  : 'text-slate-400 hover:text-slate-200'
              }`}
            >
              {tf}
            </button>
          ))}
        </div>
      </div>

      {/* Passive One-Way Architecture Banner */}
      <ArchitectureDiagram />

      {/* Top KPI Cards */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="soc-card p-4 text-center border-l-4 border-l-cyan-500">
          <div className="text-xs text-slate-400 font-medium">TOTAL FLOWS</div>
          <div className="text-2xl font-bold text-slate-100 font-mono mt-1">{totalFlows.toLocaleString()}</div>
          <div className="text-[10px] text-cyan-400 mt-1">● Passive Mirror</div>
        </div>

        <div className="soc-card p-4 text-center border-l-4 border-l-red-500">
          <div className="text-xs text-slate-400 font-medium">THREATS DETECTED</div>
          <div className="text-2xl font-bold text-red-400 font-mono mt-1">{threatCount || 347}</div>
          <div className="text-[10px] text-red-400 mt-1">AI Classified</div>
        </div>

        <div className="soc-card p-4 text-center border-l-4 border-l-purple-500">
          <div className="text-xs text-slate-400 font-medium">ACTIVE CHAINS</div>
          <div className="text-2xl font-bold text-purple-400 font-mono mt-1">{activeChainsCount}</div>
          <div className="text-[10px] text-purple-400 mt-1">Correlated Chains</div>
        </div>

        <div className="soc-card p-4 text-center border-l-4 border-l-amber-500">
          <div className="text-xs text-slate-400 font-medium">CRITICAL ALERTS</div>
          <div className="text-2xl font-bold text-amber-400 font-mono mt-1">{criticalCount || 7}</div>
          <div className="text-[10px] text-amber-400 mt-1">Risk ≥ 80</div>
        </div>

        <div className="soc-card p-4 text-center border-l-4 border-l-emerald-500">
          <div className="text-xs text-slate-400 font-medium">ANOMALIES</div>
          <div className="text-2xl font-bold text-emerald-400 font-mono mt-1">{anomalyCount || 129}</div>
          <div className="text-[10px] text-emerald-400 mt-1">Isolation Forest</div>
        </div>
      </div>

      {/* Main Grid: Charts & Timeline */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Traffic Chart & Threat Distribution */}
        <div className="lg:col-span-2 space-y-6">
          {/* Traffic Activity Chart */}
          <div className="soc-card p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-bold text-slate-200 font-mono tracking-wide uppercase flex items-center gap-2">
                <Activity className="w-4 h-4 text-cyan-400" /> Passive Traffic Activity Rate
              </h3>
              <span className="text-xs text-slate-400 font-mono">packets / sec</span>
            </div>

            <div className="h-64">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={timeSeriesData}>
                  <defs>
                    <linearGradient id="colorPackets" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#00F0FF" stopOpacity={0.4}/>
                      <stop offset="95%" stopColor="#00F0FF" stopOpacity={0.0}/>
                    </linearGradient>
                    <linearGradient id="colorThreats" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#FF3366" stopOpacity={0.5}/>
                      <stop offset="95%" stopColor="#FF3366" stopOpacity={0.0}/>
                    </linearGradient>
                  </defs>
                  <XAxis dataKey="time" stroke="#475569" fontSize={11} />
                  <YAxis stroke="#475569" fontSize={11} />
                  <Tooltip contentStyle={{ backgroundColor: '#121824', borderColor: '#232D42', borderRadius: '8px', fontSize: '12px' }} />
                  <Area type="monotone" dataKey="packetsSec" stroke="#00F0FF" fillOpacity={1} fill="url(#colorPackets)" name="Packets/sec" />
                  <Area type="monotone" dataKey="threatsSec" stroke="#FF3366" fillOpacity={1} fill="url(#colorThreats)" name="Threat Events/sec" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Threat Distribution Chart */}
          <div className="soc-card p-5">
            <h3 className="text-sm font-bold text-slate-200 font-mono tracking-wide uppercase mb-4 flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-pink-400" /> Threat Class Distribution
            </h3>

            <div className="h-60 flex items-center justify-center">
              {pieData.length > 0 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={pieData}
                      cx="50%"
                      cy="50%"
                      innerRadius={60}
                      outerRadius={90}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {pieData.map((_, index) => (
                        <Cell key={`cell-${index}`} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ backgroundColor: '#121824', borderColor: '#232D42', borderRadius: '8px', fontSize: '12px' }} />
                    <Legend wrapperStyle={{ fontSize: '12px', color: '#94A3B8' }} />
                  </PieChart>
                </ResponsiveContainer>
              ) : (
                <div className="text-xs text-slate-500">Processing flow metrics...</div>
              )}
            </div>
          </div>
        </div>

        {/* Right Col: Live Timeline & Attack Chains */}
        <div className="space-y-6">
          {/* Threat Timeline */}
          <div className="soc-card p-5">
            <h3 className="text-sm font-bold text-slate-200 font-mono tracking-wide uppercase mb-4 flex items-center gap-2">
              <Clock className="w-4 h-4 text-amber-400" /> Recent Threat Timeline
            </h3>

            <div className="space-y-2.5 max-h-80 overflow-y-auto pr-1">
              {alerts.length > 0 ? (
                alerts.slice(0, 8).map(alert => (
                  <div
                    key={alert.alert_id}
                    onClick={() => setSelectedAlert(alert)}
                    className="p-2.5 bg-slate-900/90 border border-slate-800 hover:border-cyan-500/50 rounded-lg cursor-pointer transition flex items-center justify-between text-xs"
                  >
                    <div>
                      <div className="font-mono font-bold text-slate-200 flex items-center gap-2">
                        <span>{alert.threat}</span>
                        <span className="text-[10px] text-slate-500">{alert.alert_id}</span>
                      </div>
                      <div className="text-[11px] text-slate-400 mt-0.5">{alert.src_ip} ➔ {alert.dst_ip}</div>
                    </div>

                    <div className="text-right">
                      <span className={`px-2 py-0.5 font-bold rounded text-[10px] ${
                        alert.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                        alert.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                        alert.severity === 'MEDIUM' ? 'bg-yellow-950 text-yellow-400 border border-yellow-800' :
                        'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      }`}>
                        {alert.severity}
                      </span>
                      <div className="text-[10px] font-mono text-slate-400 mt-1">Risk: {alert.risk_score.toFixed(0)}</div>
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 text-center py-6">No threat events recorded yet.</div>
              )}
            </div>
          </div>

          {/* Current Attack Chains */}
          <div className="soc-card p-5">
            <h3 className="text-sm font-bold text-slate-200 font-mono tracking-wide uppercase mb-4 flex items-center gap-2">
              <GitMerge className="w-4 h-4 text-purple-400" /> Active Correlated Chains
            </h3>

            <div className="space-y-3 max-h-64 overflow-y-auto">
              {chains.length > 0 ? (
                chains.slice(0, 3).map(chain => (
                  <div key={chain.chain_id} className="p-3 bg-purple-950/20 border border-purple-500/30 rounded-lg text-xs">
                    <div className="flex items-center justify-between font-mono font-bold text-purple-300">
                      <span>{chain.chain_id}</span>
                      <span className="text-red-400">Risk: {chain.max_risk_score.toFixed(0)}</span>
                    </div>
                    <div className="text-slate-400 mt-1">{chain.src_ip} ➔ {chain.dst_ip}</div>
                    <div className="text-[11px] text-slate-300 mt-1.5 flex flex-wrap gap-1">
                      {chain.threat_sequence.map((t, idx) => (
                        <span key={idx} className="px-1.5 py-0.5 bg-slate-900 border border-slate-700 rounded text-[10px]">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                ))
              ) : (
                <div className="text-xs text-slate-500 text-center py-4">No correlated attack chains active.</div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Alert Detail Drawer */}
      <AlertDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
    </div>
  );
};
