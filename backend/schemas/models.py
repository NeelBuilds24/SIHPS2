from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

class FlowInputSchema(BaseModel):
    timestamp: Optional[float] = Field(default=None, description="Timestamp of observed flow")
    src_ip: str = Field(default="192.168.1.100", description="Source IP address")
    dst_ip: str = Field(default="10.0.100.50", description="Destination IP address")
    src_port: Optional[int] = Field(default=54321, description="Source port")
    dst_port: Optional[int] = Field(default=80, description="Destination port")
    protocol: str = Field(default="TCP", description="IP Protocol (TCP, UDP, DNS, ICMP)")
    flow_duration: Optional[float] = Field(default=1.5, description="Flow duration in seconds")
    packets: Optional[int] = Field(default=20, description="Total packet count")
    bytes: Optional[int] = Field(default=1500, description="Total byte count")
    syn_count: Optional[int] = Field(default=1, description="TCP SYN count")
    ack_count: Optional[int] = Field(default=15, description="TCP ACK count")
    fin_count: Optional[int] = Field(default=1, description="TCP FIN count")
    rst_count: Optional[int] = Field(default=0, description="TCP RST count")
    psh_count: Optional[int] = Field(default=3, description="TCP PSH count")
    domain_name: Optional[str] = Field(default="", description="Observed DNS query string")
    inter_arrival_mean: Optional[float] = Field(default=0.1, description="Mean packet inter-arrival time (s)")
    inter_arrival_std: Optional[float] = Field(default=0.05, description="Std dev of packet inter-arrival time (s)")

class PredictionResponseSchema(BaseModel):
    threat: str
    confidence: float
    probabilities: Dict[str, float]

class AnomalyResponseSchema(BaseModel):
    anomaly_score: float
    status: str
    is_anomaly: bool

class AnalysisResponseSchema(BaseModel):
    alert_id: str
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    threat: str
    confidence: float
    anomaly_score: float
    anomaly_status: str
    risk_score: float
    severity: str
    attack_chain_id: str
    kill_chain_stage: str
    evidence: Dict[str, Any]
    forecast: Dict[str, Any]
    baseline_deviation: Dict[str, Any]
    audit_block_index: int
    dataset_type: str = "SYNTHETIC / LAB DATA"

class ReplayControlSchema(BaseModel):
    action: str = Field(..., description="Action: start, pause, stop")
    speed_multiplier: Optional[float] = Field(default=1.0, description="Speed: 1.0, 2.0, 5.0, 10.0")

class AuditTamperSchema(BaseModel):
    block_index: int = Field(default=1, description="Index of audit block to tamper with")
