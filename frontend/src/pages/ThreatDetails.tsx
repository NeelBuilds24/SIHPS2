import React from 'react';
import { ArrowLeft, ShieldAlert, Cpu, BarChart2, CheckCircle } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { ThreatType } from '../types';

interface ThreatDetailsProps {
  threatType: ThreatType;
  onBack: () => void;
}

export const ThreatDetails: React.FC<ThreatDetailsProps> = ({ threatType, onBack }) => {
  const getFeatureImportanceData = () => {
    switch (threatType) {
      case 'DNS_TUNNEL':
        return [
          { feature: 'Domain Entropy', contribution: 0.38 },
          { feature: 'Domain Length', contribution: 0.32 },
          { feature: 'Subdomain Depth', contribution: 0.18 },
          { feature: 'Query Frequency', contribution: 0.12 },
        ];
      case 'SYN_FLOOD':
        return [
          { feature: 'SYN Packet Rate', contribution: 0.42 },
          { feature: 'ACK/SYN Ratio', contribution: 0.35 },
          { feature: 'Source Diversity', contribution: 0.15 },
          { feature: 'Destination Concentration', contribution: 0.08 },
        ];
      case 'C2_BEACON':
        return [
          { feature: 'Periodicity Score', contribution: 0.45 },
          { feature: 'Inter-Arrival Time Std', contribution: 0.30 },
          { feature: 'Destination Consistency', contribution: 0.18 },
          { feature: 'Packet Size Variance', contribution: 0.07 },
        ];
      default:
        return [
          { feature: 'Packet Surge Rate', contribution: 0.40 },
          { feature: 'Protocol Variance', contribution: 0.30 },
          { feature: 'Inter-Arrival Time', contribution: 0.20 },
          { feature: 'Payload Entropy', contribution: 0.10 },
        ];
    }
  };

  const featureData = getFeatureImportanceData();

  return (
    <div className="space-y-6">
      <button
        onClick={onBack}
        className="flex items-center gap-2 text-xs font-mono text-cyan-400 hover:text-cyan-300 transition"
      >
        <ArrowLeft className="w-4 h-4" /> Back to Threat Intelligence
      </button>

      {/* Header */}
      <div className="soc-card p-6 border-cyan-500/30">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3">
              <span className="px-2.5 py-1 bg-red-950 text-red-400 border border-red-800 font-mono font-bold text-xs rounded">
                THREAT PROFILE
              </span>
              <span className="text-xs font-mono text-slate-400">NTRO PS 26145 Signature</span>
            </div>
            <h1 className="text-2xl font-bold text-slate-100 font-mono tracking-wide mt-2">
              {threatType} Detailed Analysis
            </h1>
          </div>

          <div className="flex items-center gap-6 font-mono text-center">
            <div>
              <div className="text-xs text-slate-400">Risk Score</div>
              <div className="text-2xl font-bold text-red-400">91 <span className="text-xs text-slate-500">/ 100</span></div>
            </div>
            <div>
              <div className="text-xs text-slate-400">ML Confidence</div>
              <div className="text-2xl font-bold text-cyan-400">93%</div>
            </div>
            <div>
              <div className="text-xs text-slate-400">Anomaly Level</div>
              <div className="text-2xl font-bold text-amber-400">HIGH</div>
            </div>
          </div>
        </div>
      </div>

      {/* Feature Contributions Chart */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="soc-card p-5">
          <h3 className="text-sm font-bold text-slate-200 font-mono uppercase tracking-wide mb-4 flex items-center gap-2">
            <BarChart2 className="w-4 h-4 text-cyan-400" /> Key Feature Contribution Weights (SHAP / Tree)
          </h3>

          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart layout="vertical" data={featureData} margin={{ left: 40, right: 20 }}>
                <XAxis type="number" stroke="#475569" fontSize={11} domain={[0, 0.5]} />
                <YAxis dataKey="feature" type="category" stroke="#475569" fontSize={11} width={130} />
                <Tooltip contentStyle={{ backgroundColor: '#121824', borderColor: '#232D42', borderRadius: '8px', fontSize: '12px' }} />
                <Bar dataKey="contribution" fill="#00F0FF" radius={[0, 4, 4, 0]}>
                  {featureData.map((_, index) => (
                    <Cell key={`cell-${index}`} fill={index === 0 ? '#FF3366' : '#00F0FF'} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Detection Indicators List */}
        <div className="soc-card p-5 space-y-4">
          <h3 className="text-sm font-bold text-slate-200 font-mono uppercase tracking-wide flex items-center gap-2 border-b border-border pb-3">
            <CheckCircle className="w-4 h-4 text-emerald-400" /> Behavioral Detection Indicators
          </h3>

          <div className="space-y-3 font-mono text-xs">
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between">
              <span className="text-slate-300">Domain / Payload Entropy</span>
              <span className="font-bold text-red-400 bg-red-950 px-2 py-0.5 rounded">HIGH (4.82)</span>
            </div>
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between">
              <span className="text-slate-300">Subdomain Nesting Depth</span>
              <span className="font-bold text-red-400 bg-red-950 px-2 py-0.5 rounded">HIGH (4 levels)</span>
            </div>
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between">
              <span className="text-slate-300">Query Frequency</span>
              <span className="font-bold text-amber-400 bg-amber-950 px-2 py-0.5 rounded">ELEVATED (220/min)</span>
            </div>
            <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg flex items-center justify-between">
              <span className="text-slate-300">Temporal Inter-Arrival Variance</span>
              <span className="font-bold text-emerald-400 bg-emerald-950 px-2 py-0.5 rounded">STABLE</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
