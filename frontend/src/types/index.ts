export type Severity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ThreatType = 
  | 'BENIGN'
  | 'SYN_FLOOD'
  | 'UDP_FLOOD'
  | 'SLOWLORIS'
  | 'DNS_TUNNEL'
  | 'DGA'
  | 'C2_BEACON';

export interface Alert {
  id?: number;
  alert_id: string;
  timestamp: number;
  src_ip: string;
  dst_ip: string;
  src_port?: number;
  dst_port?: number;
  protocol: string;
  threat: ThreatType;
  confidence: number;
  anomaly_score: number;
  anomaly_status?: string;
  risk_score: number;
  severity: Severity;
  attack_chain_id: string;
  evidence?: {
    threat: string;
    evidence: string[];
    ml_confidence_pct: number;
    anomaly_score: number;
    risk_score: number;
    top_shap_features?: Record<string, number>;
  };
  raw_flow?: Record<string, any>;
  dataset_type?: string;
}

export interface AttackChain {
  chain_id: string;
  created_at: number;
  last_updated: number;
  src_ip: string;
  dst_ip: string;
  event_count: number;
  max_risk_score: number;
  severity: Severity;
  status: 'ACTIVE' | 'RESOLVED';
  threat_sequence: ThreatType[];
  events: Array<{
    alert_id: string;
    timestamp: number;
    threat: ThreatType;
    risk_score: number;
    src_ip: string;
    dst_ip: string;
    protocol: string;
  }>;
}

export interface ForecastProbability {
  next_threat: ThreatType;
  probability: number;
  probability_ratio: number;
}

export interface ThreatForecast {
  current_observed_behaviour: ThreatType;
  top_predicted_next: ThreatType;
  top_probability: number;
  forecast_probabilities: ForecastProbability[];
  disclaimer: string;
}

export interface BaselineStats {
  packets_per_sec: number;
  bytes_per_sec: number;
  udp_pkt_rate_min: number;
  tcp_syn_rate_min: number;
  avg_pkt_size: number;
  dns_query_freq_min: number;
  inter_arrival_mean: number;
  sample_count: number;
}

export interface AuditBlock {
  index: number;
  timestamp: string;
  alert_id: string;
  attack_chain_id: string;
  evidence_hash: string;
  previous_hash: string;
  hash: string;
  evidence_data: Record<string, any>;
}

export interface AuditResponse {
  status: string;
  is_valid: boolean;
  chain_length: number;
  blocks: AuditBlock[];
}

export interface ReplayStatus {
  status: 'RUNNING' | 'PAUSED' | 'STOPPED';
  speed_multiplier: number;
  current_index: number;
  total_flows: number;
  processed_flows: number;
  progress_pct: number;
}

export interface ModelMetrics {
  classifier: {
    model_type: string;
    accuracy: number;
    precision: number;
    recall: number;
    f1: number;
    avg_confidence?: number;
    confusion_matrix: number[][];
    classes: string[];
  };
  anomaly_detector: {
    mean_anomaly_score: number;
    anomaly_detection_rate: number;
    flagged_anomaly_count: number;
  };
  forecaster: {
    top1_accuracy: number;
    top3_accuracy: number;
    total_evaluated_sequences: number;
  };
}
