import React, { useEffect, useState } from 'react';
import { Play, Pause, Square, Activity, Filter, Search, ShieldAlert } from 'lucide-react';
import { api } from '../services/api';
import { Alert, ReplayStatus, Severity } from '../types';
import { AlertDrawer } from '../components/AlertDrawer';

export const LiveDetection: React.FC = () => {
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [replayStatus, setReplayStatus] = useState<ReplayStatus>({
    status: 'STOPPED',
    speed_multiplier: 1.0,
    current_index: 0,
    total_flows: 300,
    processed_flows: 0,
    progress_pct: 0
  });
  const [severityFilter, setSeverityFilter] = useState<string>('ALL');
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [selectedAlert, setSelectedAlert] = useState<Alert | null>(null);

  useEffect(() => {
    fetchReplayStatus();
    fetchAlerts();
    const interval = setInterval(() => {
      fetchReplayStatus();
      fetchAlerts();
    }, 1500);
    return () => clearInterval(interval);
  }, [severityFilter]);

  const fetchReplayStatus = async () => {
    try {
      const res = await api.getReplayStatus();
      setReplayStatus(res);
    } catch (err) {
      console.error('Error fetching replay status:', err);
    }
  };

  const fetchAlerts = async () => {
    try {
      const res = await api.getAlerts(150, severityFilter === 'ALL' ? undefined : (severityFilter as Severity));
      setAlerts(res.alerts);
    } catch (err) {
      console.error('Error fetching live alerts:', err);
    }
  };

  const handleStart = async (speed: number) => {
    try {
      const res = await api.startReplay(speed);
      setReplayStatus(res);
    } catch (err) {
      console.error('Error starting replay:', err);
    }
  };

  const handlePause = async () => {
    try {
      const res = await api.pauseReplay();
      setReplayStatus(res);
    } catch (err) {
      console.error('Error pausing replay:', err);
    }
  };

  const handleStop = async () => {
    try {
      const res = await api.stopReplay();
      setReplayStatus(res);
    } catch (err) {
      console.error('Error stopping replay:', err);
    }
  };

  const filteredAlerts = alerts.filter(alert => {
    const query = searchQuery.toLowerCase();
    return (
      alert.alert_id.toLowerCase().includes(query) ||
      alert.src_ip.toLowerCase().includes(query) ||
      alert.dst_ip.toLowerCase().includes(query) ||
      alert.threat.toLowerCase().includes(query)
    );
  });

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 font-mono tracking-wide">
            Live Threat Detection
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Real-time passive one-way traffic ingestion & threat classification
          </p>
        </div>

        <div className="flex items-center gap-2 bg-emerald-950/40 border border-emerald-500/30 px-3 py-1.5 rounded-lg text-xs font-semibold text-emerald-400 font-mono">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
          </span>
          <span>STREAM ACTIVE</span>
          <span className="text-slate-600">|</span>
          <span className="text-slate-300">PASSIVE INGEST ONLY</span>
        </div>
      </div>

      {/* Replay Control Bar */}
      <div className="soc-card p-5 border-cyan-500/30">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4 mb-4">
          <div className="flex items-center gap-3">
            <button
              onClick={() => handleStart(replayStatus.speed_multiplier)}
              disabled={replayStatus.status === 'RUNNING'}
              className="px-4 py-2 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-black font-bold text-xs rounded-lg transition flex items-center gap-2 shadow-[0_0_12px_rgba(0,240,255,0.3)]"
            >
              <Play className="w-4 h-4 fill-current" /> Start Replay
            </button>

            <button
              onClick={handlePause}
              disabled={replayStatus.status !== 'RUNNING'}
              className="px-4 py-2 bg-slate-800 hover:bg-slate-700 disabled:opacity-50 text-slate-200 font-semibold text-xs rounded-lg transition flex items-center gap-2 border border-slate-700"
            >
              <Pause className="w-4 h-4" /> Pause
            </button>

            <button
              onClick={handleStop}
              className="px-4 py-2 bg-red-950/80 hover:bg-red-900 text-red-300 font-semibold text-xs rounded-lg transition flex items-center gap-2 border border-red-800"
            >
              <Square className="w-4 h-4" /> Stop
            </button>
          </div>

          {/* Speed Selector */}
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Replay Speed:</span>
            {[1.0, 2.0, 5.0, 10.0].map(speed => (
              <button
                key={speed}
                onClick={() => handleStart(speed)}
                className={`px-2.5 py-1 rounded font-bold transition ${
                  replayStatus.speed_multiplier === speed
                    ? 'bg-cyan-500 text-black'
                    : 'bg-slate-800 text-slate-400 hover:text-slate-200'
                }`}
              >
                {speed}x
              </button>
            ))}
          </div>
        </div>

        {/* Progress Bar */}
        <div className="w-full bg-slate-900 rounded-full h-2 overflow-hidden mb-2 border border-slate-800">
          <div
            className="bg-gradient-to-r from-cyan-500 to-purple-500 h-full transition-all duration-300"
            style={{ width: `${replayStatus.progress_pct}%` }}
          ></div>
        </div>

        <div className="flex justify-between text-xs text-slate-400 font-mono">
          <span>Status: <strong className="text-slate-200">{replayStatus.status}</strong></span>
          <span>Processed: <strong className="text-cyan-400">{replayStatus.processed_flows} / {replayStatus.total_flows}</strong> flows ({replayStatus.progress_pct}%)</span>
        </div>
      </div>

      {/* Filter and Search Controls */}
      <div className="flex flex-col md:flex-row items-center justify-between gap-4">
        <div className="relative w-full md:w-80">
          <Search className="w-4 h-4 absolute left-3 top-2.5 text-slate-400" />
          <input
            type="text"
            placeholder="Search IP, Alert ID, or Threat..."
            value={searchQuery}
            onChange={e => setSearchQuery(e.target.value)}
            className="w-full bg-surface border border-border rounded-lg pl-9 pr-4 py-2 text-xs text-slate-200 focus:border-cyan-500 focus:outline-none"
          />
        </div>

        <div className="flex items-center gap-2 text-xs font-mono">
          <Filter className="w-4 h-4 text-slate-400" />
          <span className="text-slate-400">Severity:</span>
          {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
            <button
              key={sev}
              onClick={() => setSeverityFilter(sev)}
              className={`px-2.5 py-1 rounded font-bold transition ${
                severityFilter === sev
                  ? 'bg-slate-700 text-cyan-400 border border-cyan-500/40'
                  : 'bg-slate-900 text-slate-400 hover:text-slate-200'
              }`}
            >
              {sev}
            </button>
          ))}
        </div>
      </div>

      {/* Live Alert Table */}
      <div className="soc-card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 uppercase border-b border-border">
              <tr>
                <th className="p-3">Alert ID</th>
                <th className="p-3">Source Endpoint</th>
                <th className="p-3">Destination Endpoint</th>
                <th className="p-3">Protocol</th>
                <th className="p-3">Threat</th>
                <th className="p-3 text-right">Confidence</th>
                <th className="p-3 text-right">Risk Score</th>
                <th className="p-3 text-center">Severity</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50 text-slate-200">
              {filteredAlerts.length > 0 ? (
                filteredAlerts.map(alert => (
                  <tr
                    key={alert.alert_id}
                    onClick={() => setSelectedAlert(alert)}
                    className="hover:bg-slate-800/60 cursor-pointer transition"
                  >
                    <td className="p-3 font-bold text-slate-300">{alert.alert_id}</td>
                    <td className="p-3 text-cyan-400">{alert.src_ip}</td>
                    <td className="p-3 text-cyan-400">{alert.dst_ip}</td>
                    <td className="p-3 text-purple-300">{alert.protocol}</td>
                    <td className="p-3 font-bold text-slate-100">{alert.threat}</td>
                    <td className="p-3 text-right font-bold text-cyan-300">{(alert.confidence * 100).toFixed(1)}%</td>
                    <td className="p-3 text-right font-bold text-amber-400">{alert.risk_score.toFixed(0)}</td>
                    <td className="p-3 text-center">
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                        alert.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                        alert.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                        alert.severity === 'MEDIUM' ? 'bg-yellow-950 text-yellow-400 border border-yellow-800' :
                        'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      }`}>
                        {alert.severity}
                      </span>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-slate-500">
                    No live threat events matched the criteria. Click '▶ Start Replay' above.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Alert Drawer */}
      <AlertDrawer alert={selectedAlert} onClose={() => setSelectedAlert(null)} />
    </div>
  );
};
