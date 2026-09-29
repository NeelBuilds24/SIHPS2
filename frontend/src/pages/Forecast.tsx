import React, { useEffect, useState } from 'react';
import { TrendingUp, AlertCircle, ArrowRight, GitCommit } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { api } from '../services/api';
import { ThreatForecast, ThreatType } from '../types';

export const Forecast: React.FC = () => {
  const [currentThreat, setCurrentThreat] = useState<ThreatType>('DNS_TUNNEL');
  const [forecast, setForecast] = useState<ThreatForecast | null>(null);

  useEffect(() => {
    fetchForecast(currentThreat);
  }, [currentThreat]);

  const fetchForecast = async (threat: ThreatType) => {
    try {
      const res = await api.getForecast(threat);
      setForecast(res);
    } catch (err) {
      console.error('Error fetching forecast:', err);
    }
  };

  const chartData = forecast?.forecast_probabilities.map(fp => ({
    name: fp.next_threat,
    probability: fp.probability
  })) || [];

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100 font-mono tracking-wide">
          Threat Evolution Forecast
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Probabilistic Markov-chain next-stage intelligence derived from correlated attack chain sequences
        </p>
      </div>

      {/* Disclaimer Banner */}
      <div className="p-4 bg-amber-950/40 border border-amber-500/40 rounded-lg flex items-center gap-3 text-xs text-amber-300">
        <AlertCircle className="w-5 h-5 flex-shrink-0 text-amber-400" />
        <span>
          <strong>Disclaimer:</strong> Forecasts are probabilistic statistical transitions based on observed passive traffic sequences. They are not guaranteed predictions.
        </span>
      </div>

      {/* Select Threat Stage */}
      <div className="soc-card p-5">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div className="flex items-center gap-3 font-mono text-xs">
            <span className="text-slate-400">Current Observed Threat Stage:</span>
            <select
              value={currentThreat}
              onChange={e => setCurrentThreat(e.target.value as ThreatType)}
              className="bg-surface border border-border rounded-lg px-4 py-2 text-slate-200 font-bold focus:border-cyan-500 focus:outline-none"
            >
              <option value="DGA">DGA (Domain Generation)</option>
              <option value="DNS_TUNNEL">DNS Tunnelling</option>
              <option value="C2_BEACON">C2 Beaconing</option>
              <option value="SLOWLORIS">Slowloris HTTP</option>
              <option value="SYN_FLOOD">SYN Flood</option>
              <option value="UDP_FLOOD">UDP Flood</option>
              <option value="BENIGN">BENIGN Baseline</option>
            </select>
          </div>

          {forecast && (
            <div className="font-mono text-xs">
              <span className="text-slate-400">Top Predicted Next Stage: </span>
              <strong className="text-cyan-400 text-sm font-bold ml-1">{forecast.top_predicted_next} ({forecast.top_probability}%)</strong>
            </div>
          )}
        </div>
      </div>

      {/* Next Stage Prediction Cards & Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Top Next Stage Cards */}
        <div className="space-y-4">
          <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wide font-mono">
            Probabilistic Next-Stage Transitions
          </h3>

          {forecast?.forecast_probabilities.map((item, idx) => (
            <div key={idx} className="soc-card p-4 flex items-center justify-between border-l-4 border-l-cyan-500">
              <div className="font-mono">
                <div className="text-xs text-slate-400">Possible Next Stage</div>
                <div className="text-sm font-bold text-slate-100 mt-0.5">{item.next_threat}</div>
              </div>
              <div className="text-right font-mono">
                <div className="text-2xl font-bold text-cyan-400">{item.probability}%</div>
                <div className="text-[10px] text-slate-500">Likelihood Ratio</div>
              </div>
            </div>
          ))}
        </div>

        {/* Right 2 Columns: Probability Bar Chart */}
        <div className="lg:col-span-2 soc-card p-5">
          <h3 className="text-sm font-bold text-slate-200 font-mono uppercase tracking-wide mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-cyan-400" /> Stage Transition Probability Distribution (%)
          </h3>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={chartData} margin={{ top: 20, right: 30, left: 0, bottom: 5 }}>
                <XAxis dataKey="name" stroke="#475569" fontSize={11} />
                <YAxis stroke="#475569" fontSize={11} domain={[0, 100]} />
                <Tooltip contentStyle={{ backgroundColor: '#121824', borderColor: '#232D42', borderRadius: '8px', fontSize: '12px' }} />
                <Bar dataKey="probability" radius={[4, 4, 0, 0]}>
                  {chartData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={index === 0 ? '#00F0FF' : index === 1 ? '#A855F7' : '#3B82F6'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>
    </div>
  );
};
