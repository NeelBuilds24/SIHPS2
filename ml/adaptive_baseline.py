import numpy as np
from typing import Dict, Any, List

class AdaptiveBaseline:
    """
    Maintains environment-specific baseline metrics derived exclusively from benign traffic.
    Excludes malicious flows from mutating baseline parameters.
    """
    def __init__(self, alpha: float = 0.05):
        # Exponential moving average factor
        self.alpha = alpha
        self.baseline_stats = {
            "packets_per_sec": 15.0,
            "bytes_per_sec": 8500.0,
            "udp_pkt_rate_min": 1200.0,
            "tcp_syn_rate_min": 60.0,
            "avg_pkt_size": 550.0,
            "dns_query_freq_min": 10.0,
            "inter_arrival_mean": 0.5,
            "sample_count": 100
        }

    def update_baseline(self, flow_dict: Dict[str, Any], is_benign: bool = True):
        """Update normal baseline if flow is classified as benign."""
        if not is_benign:
            return  # Do NOT learn from malicious traffic

        pkts_sec = float(flow_dict.get("packets_per_sec", 15.0))
        bytes_sec = float(flow_dict.get("bytes_per_sec", 8500.0))
        avg_pkt_size = float(flow_dict.get("avg_pkt_size", 550.0))
        iat_mean = float(flow_dict.get("inter_arrival_mean", 0.5))

        a = self.alpha
        self.baseline_stats["packets_per_sec"] = (1 - a) * self.baseline_stats["packets_per_sec"] + a * pkts_sec
        self.baseline_stats["bytes_per_sec"] = (1 - a) * self.baseline_stats["bytes_per_sec"] + a * bytes_sec
        self.baseline_stats["avg_pkt_size"] = (1 - a) * self.baseline_stats["avg_pkt_size"] + a * avg_pkt_size
        self.baseline_stats["inter_arrival_mean"] = (1 - a) * self.baseline_stats["inter_arrival_mean"] + a * iat_mean
        self.baseline_stats["sample_count"] += 1

    def compare_observation(self, flow_dict: Dict[str, Any]) -> Dict[str, Any]:
        """Compare current observation against baseline and compute deviation percentages."""
        protocol = str(flow_dict.get("protocol", "TCP"))
        pkts_sec = float(flow_dict.get("packets_per_sec", 0.0))
        pkts_min = pkts_sec * 60.0
        syn_count = float(flow_dict.get("syn_count", 0.0))
        syn_rate_min = syn_count * 60.0

        if protocol == "UDP":
            normal_val = self.baseline_stats["udp_pkt_rate_min"]
            obs_val = pkts_min
            metric_name = "UDP Packet Rate (pkts/min)"
        elif protocol == "TCP" and syn_count > 10:
            normal_val = self.baseline_stats["tcp_syn_rate_min"]
            obs_val = syn_rate_min
            metric_name = "TCP SYN Rate (SYNs/min)"
        else:
            normal_val = self.baseline_stats["packets_per_sec"]
            obs_val = pkts_sec
            metric_name = "Packets / sec"

        deviation_pct = ((obs_val - normal_val) / (normal_val + 1e-5)) * 100.0

        if deviation_pct >= 500.0:
            status = "CRITICAL"
        elif deviation_pct >= 200.0:
            status = "HIGH"
        elif deviation_pct >= 50.0:
            status = "ELEVATED"
        else:
            status = "NORMAL"

        return {
            "metric": metric_name,
            "baseline_value": round(normal_val, 2),
            "observed_value": round(obs_val, 2),
            "deviation_pct": round(deviation_pct, 1),
            "status": status,
            "all_baseline_stats": {k: round(v, 2) for k, v in self.baseline_stats.items()}
        }
