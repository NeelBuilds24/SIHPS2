import time
from typing import Dict, Any, List, Optional

class CorrelationEngine:
    """Correlates passive security events into multi-stage attack chains."""
    def __init__(self, time_window_sec: float = 600.0):
        self.time_window_sec = time_window_sec
        self.chains: Dict[str, Dict[str, Any]] = {}
        self.chain_counter = 1

    def process_event(self, alert_data: Dict[str, Any]) -> str:
        """Process an alert event and assign to an existing or new attack chain."""
        src_ip = alert_data.get("src_ip", "0.0.0.0")
        dst_ip = alert_data.get("dst_ip", "0.0.0.0")
        threat = alert_data.get("threat", "BENIGN")
        risk = float(alert_data.get("risk_score", 0.0))
        timestamp = float(alert_data.get("timestamp", time.time()))

        if threat == "BENIGN" and risk < 50.0:
            return ""

        # Find matching active chain by src_ip or (src_ip, dst_ip) within time window
        matched_chain_id = None
        for chain_id, chain in list(self.chains.items()):
            if chain["status"] == "ACTIVE":
                if (chain["src_ip"] == src_ip or chain["dst_ip"] == dst_ip) and \
                   (timestamp - chain["last_updated"]) <= self.time_window_sec:
                    matched_chain_id = chain_id
                    break

        if not matched_chain_id:
            matched_chain_id = f"CHAIN-{self.chain_counter:05d}"
            self.chain_counter += 1
            self.chains[matched_chain_id] = {
                "chain_id": matched_chain_id,
                "created_at": timestamp,
                "last_updated": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "event_count": 0,
                "threat_sequence": [],
                "max_risk_score": 0.0,
                "severity": "LOW",
                "status": "ACTIVE",
                "events": []
            }

        chain = self.chains[matched_chain_id]
        chain["last_updated"] = timestamp
        chain["event_count"] += 1
        
        if threat not in chain["threat_sequence"]:
            chain["threat_sequence"].append(threat)
            
        chain["max_risk_score"] = max(chain["max_risk_score"], risk)
        
        if chain["max_risk_score"] >= 80.0:
            chain["severity"] = "CRITICAL"
        elif chain["max_risk_score"] >= 60.0:
            chain["severity"] = "HIGH"
        elif chain["max_risk_score"] >= 30.0:
            chain["severity"] = "MEDIUM"

        chain["events"].append({
            "alert_id": alert_data.get("alert_id", ""),
            "timestamp": timestamp,
            "threat": threat,
            "risk_score": risk,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": alert_data.get("protocol", "TCP")
        })

        return matched_chain_id

    def get_all_chains(self) -> List[Dict[str, Any]]:
        return list(self.chains.values())

    def get_chain(self, chain_id: str) -> Optional[Dict[str, Any]]:
        return self.chains.get(chain_id)
