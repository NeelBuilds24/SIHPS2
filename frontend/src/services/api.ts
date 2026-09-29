import axios from 'axios';
import {
  Alert,
  AttackChain,
  ThreatForecast,
  BaselineStats,
  AuditResponse,
  ReplayStatus,
  ModelMetrics,
  Severity
} from '../types';

const API_BASE_URL = 'http://localhost:8000';

export const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

export const api = {
  // Health
  getHealth: async () => {
    const res = await apiClient.get('/health');
    return res.data;
  },

  // Alerts
  getAlerts: async (limit = 100, severity?: Severity): Promise<{ count: number; alerts: Alert[] }> => {
    const params: Record<string, any> = { limit };
    if (severity && severity !== ('ALL' as any)) params.severity = severity;
    const res = await apiClient.get('/alerts', { params });
    return res.data;
  },

  getAlertById: async (alertId: string): Promise<Alert> => {
    const res = await apiClient.get(`/alerts/${alertId}`);
    return res.data;
  },

  // Attack Chains
  getAttackChains: async (): Promise<{ count: number; attack_chains: AttackChain[] }> => {
    const res = await apiClient.get('/attack-chains');
    return res.data;
  },

  getAttackChainById: async (chainId: string): Promise<AttackChain> => {
    const res = await apiClient.get(`/attack-chains/${chainId}`);
    return res.data;
  },

  getAttackGraph: async (chainId: string) => {
    const res = await apiClient.get(`/attack-graph/${chainId}`);
    return res.data;
  },

  // Forecast
  getForecast: async (threatType: string): Promise<ThreatForecast> => {
    const res = await apiClient.get(`/forecast/${threatType}`);
    return res.data;
  },

  // Baseline
  getBaseline: async (): Promise<BaselineStats> => {
    const res = await apiClient.get('/baseline');
    return res.data;
  },

  // Audit Ledger
  getAuditLedger: async (): Promise<AuditResponse> => {
    const res = await apiClient.get('/audit');
    return res.data;
  },

  verifyAuditChain: async () => {
    const res = await apiClient.get('/audit/verify');
    return res.data;
  },

  simulateTampering: async (blockIndex = 1) => {
    const res = await apiClient.post('/audit/tamper', { block_index: blockIndex });
    return res.data;
  },

  // Replay
  startReplay: async (speedMultiplier = 1.0): Promise<ReplayStatus> => {
    const res = await apiClient.post('/replay/start', { action: 'start', speed_multiplier: speedMultiplier });
    return res.data;
  },

  pauseReplay: async (): Promise<ReplayStatus> => {
    const res = await apiClient.post('/replay/pause', { action: 'pause' });
    return res.data;
  },

  stopReplay: async (): Promise<ReplayStatus> => {
    const res = await apiClient.post('/replay/stop', { action: 'stop' });
    return res.data;
  },

  getReplayStatus: async (): Promise<ReplayStatus> => {
    const res = await apiClient.get('/replay/status');
    return res.data;
  },

  // Model Metrics
  getModelMetrics: async (): Promise<ModelMetrics> => {
    const res = await apiClient.get('/metrics');
    return res.data;
  },

  // Upload CSV
  uploadCSV: async (file: File) => {
    const formData = new FormData();
    formData.append('file', file);
    const res = await apiClient.post('/upload', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    });
    return res.data;
  }
};
