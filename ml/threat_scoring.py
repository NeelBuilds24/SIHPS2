from typing import Dict, Any, Tuple
from ml.feature_extraction import extract_features_from_dict

DEFAULT_WEIGHTS = {
    "ml_confidence": 0.40,
    "anomaly_score": 0.30,
    "behavioral": 0.20,
    "temporal": 0.10
}

class HybridRiskScorer:
    """Calculates transparent 0-100 risk score and severity level based on weighted indicators."""
    def __init__(self, weights: Dict[str, float] = None):
        self.weights = weights or DEFAULT_WEIGHTS.copy()
        self._normalize_weights()

    def update_weights(self, weights: Dict[str, float]):
        self.weights.update(weights)
        self._normalize_weights()

    def _normalize_weights(self):
        total = sum(self.weights.values())
        if total > 0:
            self.weights = {k: v / total for k, v in self.weights.items()}

    def calculate_behavioral_score(self, feats: Dict[str, float], predicted_class: str) -> float:
        """Compute behavioral risk score 0.0 - 1.0."""
        score = 0.0
        
        # High dest concentration or source diversity
        if feats["dest_concentration"] > 0.8:
            score += 0.3
        if feats["source_diversity"] > 20.0:
            score += 0.3
            
        # Specific threat behavioral markers
        if predicted_class == "SYN_FLOOD" and feats["ack_syn_ratio"] < 0.2:
            score += 0.4
        elif predicted_class == "UDP_FLOOD" and feats["packets_per_sec"] > 1000:
            score += 0.4
        elif predicted_class == "DNS_TUNNEL" and feats["dns_tunnel_score"] > 50:
            score += (feats["dns_tunnel_score"] / 100.0) * 0.4
        elif predicted_class == "DGA" and feats["dga_score"] > 50:
            score += (feats["dga_score"] / 100.0) * 0.4
        elif predicted_class == "C2_BEACON" and feats["c2_beacon_score"] > 50:
            score += (feats["c2_beacon_score"] / 100.0) * 0.4
        elif predicted_class == "SLOWLORIS" and feats["flow_duration"] > 100:
            score += 0.4
        
        return min(1.0, score)

    def calculate_temporal_score(self, feats: Dict[str, float]) -> float:
        """Compute temporal risk score 0.0 - 1.0 based on inter-arrival times and periodicity."""
        score = 0.0
        # High periodicity or extreme burstiness
        if feats["periodicity_score"] > 70.0:
            score += 0.5
        if feats["burstiness"] > 5.0:
            score += 0.5
        if feats["inter_arrival_std"] < 0.01:
            score += 0.3
        return min(1.0, score)

    def compute_risk(
        self,
        predicted_class: str,
        ml_confidence: float,
        anomaly_score: float,
        flow_dict: Dict[str, Any]
    ) -> Tuple[float, str, Dict[str, float]]:
        """
        Compute total risk score (0-100), severity level, and subcomponent breakdown.
        """
        feats = extract_features_from_dict(flow_dict)
        
        # If class is BENIGN and anomaly score is very low, suppress risk
        if predicted_class == "BENIGN" and anomaly_score < 0.4:
            ml_component = ml_confidence * 0.05
        else:
            ml_component = ml_confidence

        beh_score = self.calculate_behavioral_score(feats, predicted_class)
        temp_score = self.calculate_temporal_score(feats)

        # Weighted calculation
        total_risk_val = (
            self.weights["ml_confidence"] * ml_component +
            self.weights["anomaly_score"] * anomaly_score +
            self.weights["behavioral"] * beh_score +
            self.weights["temporal"] * temp_score
        ) * 100.0

        risk_score = round(float(max(0.0, min(100.0, total_risk_val))), 2)

        if risk_score >= 80.0:
            severity = "CRITICAL"
        elif risk_score >= 60.0:
            severity = "HIGH"
        elif risk_score >= 30.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        breakdown = {
            "ml_confidence_weight": round(self.weights["ml_confidence"], 2),
            "ml_confidence_value": round(ml_component, 4),
            "anomaly_score_weight": round(self.weights["anomaly_score"], 2),
            "anomaly_score_value": round(anomaly_score, 4),
            "behavioral_weight": round(self.weights["behavioral"], 2),
            "behavioral_value": round(beh_score, 4),
            "temporal_weight": round(self.weights["temporal"], 2),
            "temporal_value": round(temp_score, 4)
        }

        return risk_score, severity, breakdown
