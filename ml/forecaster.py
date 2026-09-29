import os
import joblib
import numpy as np
from typing import Dict, Any, List, Tuple

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

DEFAULT_TRANSITIONS = {
    "DGA": {
        "DNS_TUNNEL": 0.55,
        "C2_BEACON": 0.30,
        "SYN_FLOOD": 0.10,
        "BENIGN": 0.05
    },
    "DNS_TUNNEL": {
        "C2_BEACON": 0.62,
        "SYN_FLOOD": 0.23,
        "UDP_FLOOD": 0.10,
        "BENIGN": 0.05
    },
    "C2_BEACON": {
        "DNS_TUNNEL": 0.45,
        "SYN_FLOOD": 0.35,
        "UDP_FLOOD": 0.15,
        "BENIGN": 0.05
    },
    "SLOWLORIS": {
        "SYN_FLOOD": 0.50,
        "UDP_FLOOD": 0.30,
        "C2_BEACON": 0.15,
        "BENIGN": 0.05
    },
    "SYN_FLOOD": {
        "UDP_FLOOD": 0.60,
        "C2_BEACON": 0.25,
        "BENIGN": 0.15
    },
    "UDP_FLOOD": {
        "SYN_FLOOD": 0.55,
        "C2_BEACON": 0.30,
        "BENIGN": 0.15
    },
    "BENIGN": {
        "BENIGN": 0.70,
        "DGA": 0.10,
        "DNS_TUNNEL": 0.10,
        "C2_BEACON": 0.10
    }
}

class MarkovThreatForecaster:
    """Lightweight Markov-Chain Probabilistic Next-Stage Threat Forecaster."""
    def __init__(self):
        self.transitions = DEFAULT_TRANSITIONS.copy()

    def train_from_sequences(self, attack_sequences: List[List[str]]):
        """Fit transition matrix from observed attack chain threat sequences."""
        counts = {}
        for seq in attack_sequences:
            for i in range(len(seq) - 1):
                curr, nxt = seq[i], seq[i + 1]
                if curr not in counts:
                    counts[curr] = {}
                counts[curr][nxt] = counts[curr].get(nxt, 0) + 1

        for curr, nxt_dict in counts.items():
            total = sum(nxt_dict.values())
            if total > 0:
                self.transitions[curr] = {k: round(v / total, 4) for k, v in nxt_dict.items()}

        self.save()

    def predict_next_stage(self, current_threat: str) -> Dict[str, Any]:
        """
        Return next stage probabilities for a given current threat state.
        Includes disclaimers and structured forecast output.
        """
        trans = self.transitions.get(current_threat, self.transitions.get("BENIGN"))
        
        # Format top predictions sorted by probability
        predictions = []
        for next_threat, prob in sorted(trans.items(), key=lambda x: x[1], reverse=True):
            predictions.append({
                "next_threat": next_threat,
                "probability": round(prob * 100.0, 1),
                "probability_ratio": round(prob, 4)
            })

        top_next = predictions[0]["next_threat"] if predictions else "Unknown"
        top_prob = predictions[0]["probability"] if predictions else 0.0

        return {
            "current_observed_behaviour": current_threat,
            "top_predicted_next": top_next,
            "top_probability": top_prob,
            "forecast_probabilities": predictions,
            "disclaimer": "Probabilistic Forecast — Not a Guaranteed Prediction"
        }

    def save(self, filepath: str = None):
        if filepath is None:
            os.makedirs(MODEL_DIR, exist_ok=True)
            filepath = os.path.join(MODEL_DIR, "threat_forecaster.joblib")
        joblib.dump({"transitions": self.transitions}, filepath)

    def load(self, filepath: str = None) -> bool:
        if filepath is None:
            filepath = os.path.join(MODEL_DIR, "threat_forecaster.joblib")
        if not os.path.exists(filepath):
            return False
        try:
            data = joblib.load(filepath)
            self.transitions = data["transitions"]
            return True
        except Exception:
            return False
