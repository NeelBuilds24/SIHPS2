import React, { useEffect, useState } from 'react';
import { GitMerge, ShieldAlert, ArrowRight, Clock, CheckCircle } from 'lucide-react';
import { api } from '../services/api';
import { AttackChain, Severity } from '../types';

export const AttackChains: React.FC = () => {
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [selectedChain, setSelectedChain] = useState<AttackChain | null>(null);
  const [filterSeverity, setFilterSeverity] = useState<string>('ALL');

  useEffect(() => {
    fetchChains();
  }, []);

  const fetchChains = async () => {
    try {
      const res = await api.getAttackChains();
      setChains(res.attack_chains);
      if (res.attack_chains.length > 0) {
        setSelectedChain(res.attack_chains[0]);
      }
    } catch (err) {
      console.error('Error fetching attack chains:', err);
    }
  };

  const filteredChains = chains.filter(c => {
    if (filterSeverity === 'ALL') return true;
    return c.severity === filterSeverity;
  });

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-slate-100 font-mono tracking-wide">
          Correlated Attack Chains
        </h1>
        <p className="text-xs text-slate-400 mt-1">
          Multi-stage passive event correlation grouping observations into persistent attack chains
        </p>
      </div>

      {/* Severity Filter */}
      <div className="flex items-center gap-2 text-xs font-mono">
        <span className="text-slate-400">Filter Severity:</span>
        {['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map(sev => (
          <button
            key={sev}
            onClick={() => setFilterSeverity(sev)}
            className={`px-3 py-1 rounded font-bold transition ${
              filterSeverity === sev
                ? 'bg-purple-600 text-white shadow-[0_0_10px_rgba(168,85,247,0.4)]'
                : 'bg-slate-900 text-slate-400 hover:text-slate-200 border border-slate-800'
            }`}
          >
            {sev}
          </button>
        ))}
      </div>

      {/* Main Grid: Chain Cards & Detail View */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left Column: Chain List */}
        <div className="space-y-4">
          <h2 className="text-xs font-bold text-slate-400 uppercase tracking-wide font-mono">
            Active Attack Chains ({filteredChains.length})
          </h2>

          <div className="space-y-3 max-h-[600px] overflow-y-auto pr-1">
            {filteredChains.length > 0 ? (
              filteredChains.map(chain => {
                const isSelected = selectedChain?.chain_id === chain.chain_id;
                return (
                  <div
                    key={chain.chain_id}
                    onClick={() => setSelectedChain(chain)}
                    className={`p-4 rounded-lg cursor-pointer transition soc-card ${
                      isSelected
                        ? 'border-purple-500 bg-purple-950/20 shadow-[0_0_15px_rgba(168,85,247,0.15)]'
                        : 'hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-center justify-between font-mono">
                      <span className="font-bold text-slate-100 flex items-center gap-2">
                        <GitMerge className="w-4 h-4 text-purple-400" />
                        {chain.chain_id}
                      </span>
                      <span className={`px-2 py-0.5 text-[10px] font-bold rounded ${
                        chain.severity === 'CRITICAL' ? 'bg-red-950 text-red-400 border border-red-800' :
                        chain.severity === 'HIGH' ? 'bg-orange-950 text-orange-400 border border-orange-800' :
                        chain.severity === 'MEDIUM' ? 'bg-yellow-950 text-yellow-400 border border-yellow-800' :
                        'bg-emerald-950 text-emerald-400 border border-emerald-800'
                      }`}>
                        {chain.severity}
                      </span>
                    </div>

                    <div className="grid grid-cols-3 gap-2 my-3 text-center text-xs font-mono">
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <div className="text-slate-500 text-[10px]">Risk</div>
                        <div className="font-bold text-red-400">{chain.max_risk_score.toFixed(0)}</div>
                      </div>
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <div className="text-slate-500 text-[10px]">Events</div>
                        <div className="font-bold text-cyan-400">{chain.event_count}</div>
                      </div>
                      <div className="p-2 bg-slate-900 rounded border border-slate-800">
                        <div className="text-slate-500 text-[10px]">Status</div>
                        <div className="font-bold text-emerald-400">{chain.status}</div>
                      </div>
                    </div>

                    <div className="text-xs text-slate-400 font-mono">
                      {chain.src_ip} ➔ {chain.dst_ip}
                    </div>

                    <div className="flex flex-wrap gap-1 mt-2">
                      {chain.threat_sequence.map((t, idx) => (
                        <span key={idx} className="px-2 py-0.5 bg-slate-900 border border-slate-700 rounded text-[10px] font-mono text-purple-300">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="p-8 text-center text-xs text-slate-500 soc-card">
                No attack chains matching criteria.
              </div>
            )}
          </div>
        </div>

        {/* Right 2 Columns: Selected Chain Details */}
        <div className="lg:col-span-2">
          {selectedChain ? (
            <div className="soc-card p-6 space-y-6">
              {/* Chain Header */}
              <div className="flex items-center justify-between border-b border-border pb-4">
                <div>
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xl font-bold text-purple-300">{selectedChain.chain_id}</span>
                    <span className="px-2.5 py-0.5 bg-emerald-950 text-emerald-400 border border-emerald-800 font-mono font-bold text-xs rounded">
                      {selectedChain.status} ATTACK CHAIN
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1 font-mono">
                    Endpoints: <strong className="text-cyan-300">{selectedChain.src_ip}</strong> ➔ <strong className="text-cyan-300">{selectedChain.dst_ip}</strong>
                  </p>
                </div>

                <div className="text-right">
                  <div className="text-xs text-slate-400">Peak Risk Score</div>
                  <div className="text-3xl font-bold font-mono text-red-400">
                    {selectedChain.max_risk_score.toFixed(0)} <span className="text-xs text-slate-500">/ 100</span>
                  </div>
                </div>
              </div>

              {/* Threat Progression */}
              <div>
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wide font-mono mb-3">
                  Threat Stage Progression Sequence
                </h3>

                <div className="flex items-center gap-2 overflow-x-auto pb-2">
                  <div className="p-3 bg-slate-900 border border-slate-800 rounded-lg text-xs font-mono text-slate-400">
                    Observed Start
                  </div>
                  {selectedChain.threat_sequence.map((threat, idx) => (
                    <React.Fragment key={idx}>
                      <ArrowRight className="w-4 h-4 text-purple-400 flex-shrink-0" />
                      <div className="p-3 bg-purple-950/40 border border-purple-500/40 rounded-lg text-xs font-mono font-bold text-purple-200">
                        {threat}
                      </div>
                    </React.Fragment>
                  ))}
                </div>
              </div>

              {/* Chain Event Timeline */}
              <div>
                <h3 className="text-xs font-bold text-slate-300 uppercase tracking-wide font-mono mb-3 flex items-center gap-2">
                  <Clock className="w-4 h-4 text-cyan-400" /> Correlated Event Sequence Timeline
                </h3>

                <div className="space-y-3 relative before:absolute before:inset-0 before:left-3.5 before:w-0.5 before:bg-slate-800">
                  {selectedChain.events.map((event, idx) => (
                    <div key={idx} className="relative flex items-start gap-4 pl-8 text-xs font-mono">
                      <div className="absolute left-2 top-1.5 w-3 h-3 rounded-full bg-purple-500 border-2 border-slate-950"></div>
                      <div className="p-3 bg-slate-900/90 border border-slate-800 rounded-lg w-full flex items-center justify-between">
                        <div>
                          <span className="font-bold text-slate-200">{event.threat}</span>
                          <span className="text-slate-500 ml-2">[{event.alert_id}]</span>
                          <div className="text-[11px] text-slate-400 mt-0.5">
                            {event.src_ip} ➔ {event.dst_ip} ({event.protocol})
                          </div>
                        </div>
                        <div className="text-right">
                          <span className="font-bold text-red-400">Risk: {event.risk_score.toFixed(0)}</span>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          ) : (
            <div className="soc-card p-12 text-center text-slate-500 text-xs">
              Select an attack chain on the left to inspect timeline and details.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
