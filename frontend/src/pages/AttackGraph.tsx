import React, { useEffect, useState, useCallback } from 'react';
import {
  ReactFlow,
  MiniMap,
  Controls,
  Background,
  useNodesState,
  useEdgesState,
  Node,
  Edge,
  Position,
  Handle
} from '@xyflow/react';
import '@xyflow/react/dist/style.css';
import { Share2, ShieldAlert, Cpu, Network, Info } from 'lucide-react';
import { api } from '../services/api';
import { AttackChain } from '../types';

// Custom Custom Node Component
const SecurityNode = ({ data }: { data: any }) => {
  const isThreat = data.type === 'THREAT';
  const isSource = data.type === 'IP_SOURCE';
  
  const borderColor = isThreat
    ? 'border-red-500 shadow-[0_0_15px_rgba(239,68,68,0.3)] bg-red-950/80'
    : isSource
    ? 'border-purple-500 shadow-[0_0_15px_rgba(168,85,247,0.3)] bg-purple-950/80'
    : 'border-cyan-500 shadow-[0_0_15px_rgba(0,240,255,0.3)] bg-cyan-950/80';

  return (
    <div className={`p-3 rounded-lg border-2 min-w-[140px] text-center font-mono text-xs font-bold text-slate-100 ${borderColor}`}>
      <Handle type="target" position={Position.Top} className="w-2 h-2 bg-slate-400" />
      <div className="text-[10px] text-slate-400 uppercase tracking-wider mb-0.5">{data.type}</div>
      <div className="truncate">{data.label}</div>
      {data.risk !== undefined && (
        <div className="text-[10px] text-red-400 mt-1 font-semibold">Risk: {data.risk.toFixed(0)}</div>
      )}
      <Handle type="source" position={Position.Bottom} className="w-2 h-2 bg-slate-400" />
    </div>
  );
};

const nodeTypes = {
  securityNode: SecurityNode,
};

export const AttackGraph: React.FC = () => {
  const [chains, setChains] = useState<AttackChain[]>([]);
  const [selectedChainId, setSelectedChainId] = useState<string>('');
  const [nodes, setNodes, onNodesChange] = useNodesState<Node>([]);
  const [edges, setEdges, onEdgesChange] = useEdgesState<Edge>([]);
  const [selectedNodeData, setSelectedNodeData] = useState<any | null>(null);

  useEffect(() => {
    fetchChains();
  }, []);

  const fetchChains = async () => {
    try {
      const res = await api.getAttackChains();
      setChains(res.attack_chains);
      if (res.attack_chains.length > 0) {
        setSelectedChainId(res.attack_chains[0].chain_id);
        buildGraphFromChain(res.attack_chains[0]);
      } else {
        buildDefaultGraph();
      }
    } catch (err) {
      console.error('Error fetching chains for graph:', err);
      buildDefaultGraph();
    }
  };

  const handleChainChange = (chainId: string) => {
    setSelectedChainId(chainId);
    const chain = chains.find(c => c.chain_id === chainId);
    if (chain) {
      buildGraphFromChain(chain);
    }
  };

  const buildGraphFromChain = (chain: AttackChain) => {
    const newNodes: Node[] = [
      {
        id: chain.src_ip,
        type: 'securityNode',
        position: { x: 250, y: 50 },
        data: { label: chain.src_ip, type: 'IP_SOURCE', risk: chain.max_risk_score }
      },
      {
        id: chain.dst_ip,
        type: 'securityNode',
        position: { x: 250, y: 350 },
        data: { label: chain.dst_ip, type: 'IP_TARGET', risk: 0 }
      }
    ];

    const newEdges: Edge[] = [];

    chain.threat_sequence.forEach((threat, idx) => {
      const threatNodeId = `THREAT-${threat}-${idx}`;
      newNodes.push({
        id: threatNodeId,
        type: 'securityNode',
        position: { x: 100 + idx * 180, y: 200 },
        data: { label: threat, type: 'THREAT', risk: chain.max_risk_score }
      });

      newEdges.push({
        id: `e-src-${threatNodeId}`,
        source: chain.src_ip,
        target: threatNodeId,
        animated: true,
        style: { stroke: '#A855F7', strokeWidth: 2 }
      });

      newEdges.push({
        id: `e-${threatNodeId}-dst`,
        source: threatNodeId,
        target: chain.dst_ip,
        animated: true,
        style: { stroke: '#FF3366', strokeWidth: 2 }
      });
    });

    setNodes(newNodes);
    setEdges(newEdges);
  };

  const buildDefaultGraph = () => {
    const defaultNodes: Node[] = [
      { id: '192.168.1.120', type: 'securityNode', position: { x: 250, y: 50 }, data: { label: '192.168.1.120', type: 'IP_SOURCE', risk: 85 } },
      { id: 'DNS_TUNNEL', type: 'securityNode', position: { x: 100, y: 200 }, data: { label: 'DNS_TUNNEL', type: 'THREAT', risk: 91 } },
      { id: 'C2_BEACON', type: 'securityNode', position: { x: 400, y: 200 }, data: { label: 'C2_BEACON', type: 'THREAT', risk: 87 } },
      { id: '10.0.100.50', type: 'securityNode', position: { x: 250, y: 350 }, data: { label: '10.0.100.50', type: 'IP_TARGET', risk: 0 } }
    ];

    const defaultEdges: Edge[] = [
      { id: 'e1', source: '192.168.1.120', target: 'DNS_TUNNEL', animated: true, style: { stroke: '#A855F7', strokeWidth: 2 } },
      { id: 'e2', source: 'DNS_TUNNEL', target: 'C2_BEACON', animated: true, style: { stroke: '#FF3366', strokeWidth: 2 } },
      { id: 'e3', source: 'C2_BEACON', target: '10.0.100.50', animated: true, style: { stroke: '#00F0FF', strokeWidth: 2 } }
    ];

    setNodes(defaultNodes);
    setEdges(defaultEdges);
  };

  const onNodeClick = useCallback((_: any, node: Node) => {
    setSelectedNodeData(node.data);
  }, []);

  return (
    <div className="space-y-6">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-slate-100 font-mono tracking-wide">
            Interactive Attack Graph (React Flow)
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Correlated passive entity topology displaying source IPs, target enclave IPs, and threat behaviors
          </p>
        </div>

        {chains.length > 0 && (
          <div className="flex items-center gap-2 text-xs font-mono">
            <span className="text-slate-400">Select Attack Chain:</span>
            <select
              value={selectedChainId}
              onChange={e => handleChainChange(e.target.value)}
              className="bg-surface border border-border rounded-lg px-3 py-1.5 text-slate-200 focus:border-cyan-500 focus:outline-none"
            >
              {chains.map(c => (
                <option key={c.chain_id} value={c.chain_id}>
                  {c.chain_id} ({c.src_ip} ➔ {c.dst_ip})
                </option>
              ))}
            </select>
          </div>
        )}
      </div>

      {/* Legend Bar */}
      <div className="flex items-center gap-6 p-3 bg-slate-900 border border-border rounded-lg text-xs font-mono">
        <span className="text-slate-400 font-bold">Node Legend:</span>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-purple-500"></span>
          <span className="text-slate-300">Source IP</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-red-500"></span>
          <span className="text-slate-300">Threat / Attack Behavior</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="w-3 h-3 rounded-full bg-cyan-500"></span>
          <span className="text-slate-300">Target Enclave IP</span>
        </div>
      </div>

      {/* React Flow Container */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="lg:col-span-3 soc-card h-[520px] relative overflow-hidden">
          <ReactFlow
            nodes={nodes}
            edges={edges}
            onNodesChange={onNodesChange}
            onEdgesChange={onEdgesChange}
            onNodeClick={onNodeClick}
            nodeTypes={nodeTypes}
            fitView
          >
            <Controls className="bg-slate-900 border-border text-slate-200" />
            <MiniMap style={{ backgroundColor: '#0A0D14' }} nodeColor="#232D42" />
            <Background color="#232D42" gap={20} />
          </ReactFlow>
        </div>

        {/* Right Inspector Side Panel */}
        <div className="soc-card p-5 space-y-4 font-mono text-xs">
          <h3 className="text-sm font-bold text-slate-200 uppercase tracking-wide flex items-center gap-2 border-b border-border pb-3">
            <Info className="w-4 h-4 text-cyan-400" /> Node Inspector
          </h3>

          {selectedNodeData ? (
            <div className="space-y-3">
              <div>
                <div className="text-slate-500">NODE LABEL</div>
                <div className="text-sm font-bold text-cyan-300">{selectedNodeData.label}</div>
              </div>
              <div>
                <div className="text-slate-500">NODE TYPE</div>
                <div className="font-bold text-slate-200">{selectedNodeData.type}</div>
              </div>
              {selectedNodeData.risk !== undefined && (
                <div>
                  <div className="text-slate-500">MAX RISK SCORE</div>
                  <div className="text-lg font-bold text-red-400">{selectedNodeData.risk.toFixed(0)} / 100</div>
                </div>
              )}
              <div className="p-3 bg-slate-900 border border-slate-800 rounded text-[11px] text-slate-400">
                🔒 Relationship derived strictly from passive mirror ingestion. No network probes or outbound socket handshakes were performed.
              </div>
            </div>
          ) : (
            <div className="text-slate-500 py-8 text-center">
              Click any graph node to inspect metadata.
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
