import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, Tuple
from sklearn.ensemble import IsolationForest

from ml.preprocessing import Preprocessor
from ml.feature_extraction import FEATURE_COLUMNS, extract_features_from_dict

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

class AnomalyDetector:
    """Isolation Forest Anomaly Detector for identifying novel or unknown threat patterns."""
    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.preprocessor = Preprocessor()
        self.model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42
        )
        self.is_trained = False

    def train(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Train Isolation Forest model primarily on benign baseline flows."""
        os.makedirs(MODEL_DIR, exist_ok=True)
        # Filter benign if label exists, else use full set
        if "label" in df.columns:
            benign_df = df[df["label"] == "BENIGN"]
            train_df = benign_df if len(benign_df) > 50 else df
        else:
            train_df = df

        X_scaled, _ = self.preprocessor.fit_transform(train_df)
        self.model.fit(X_scaled)
        self.is_trained = True

        self.save()

        # Compute training scores
        scores = self.model.decision_function(X_scaled)
        return {
            "contamination": self.contamination,
            "trained_samples": len(train_df),
            "mean_score": round(float(np.mean(scores)), 4),
            "min_score": round(float(np.min(scores)), 4)
        }

    def predict_single(self, flow_dict: Dict[str, Any]) -> Tuple[float, str, bool]:
        """
        Calculate anomaly score [0.0, 1.0] and anomaly status for a single flow.
        Higher score indicates higher degree of anomaly.
        """
        if not self.is_trained:
            if not self.load():
                return self._rule_based_anomaly(flow_dict)

        feats_dict = extract_features_from_dict(flow_dict)
        df_single = pd.DataFrame([feats_dict])
        X_scaled = self.preprocessor.transform(df_single)

        # Isolation forest decision_function returns negative for outliers, positive for inliers
        raw_score = self.model.decision_function(X_scaled)[0]
        
        # Convert raw_score (approx -0.5 to 0.5) to [0.0, 1.0] normalized anomaly score
        # raw_score of -0.3 or below is extreme anomaly (1.0), raw_score of +0.2 is normal (0.0)
        norm_score = float(np.clip((0.25 - raw_score) / 0.55, 0.0, 1.0))
        norm_score = round(norm_score, 4)

        is_anomaly = bool(norm_score > 0.50)

        if norm_score >= 0.80:
            status = "HIGHLY ANOMALOUS"
        elif norm_score >= 0.60:
            status = "ANOMALOUS"
        elif norm_score >= 0.40:
            status = "SUSPICIOUS"
        else:
            status = "NORMAL"

        return norm_score, status, is_anomaly

    def _rule_based_anomaly(self, flow_dict: Dict[str, Any]) -> Tuple[float, str, bool]:
        feats = extract_features_from_dict(flow_dict)
        score = 0.1
        if feats["packets_per_sec"] > 3000 or feats["bytes_per_sec"] > 5_000_000:
            score += 0.5
        if feats["dns_tunnel_score"] > 60 or feats["dga_score"] > 60:
            score += 0.35
        if feats["c2_beacon_score"] > 70:
            score += 0.35
        if feats["syn_ratio"] > 0.8:
            score += 0.4

        score = min(1.0, score)
        is_anomaly = score > 0.5

        if score >= 0.80:
            status = "HIGHLY ANOMALOUS"
        elif score >= 0.60:
            status = "ANOMALOUS"
        elif score >= 0.40:
            status = "SUSPICIOUS"
        else:
            status = "NORMAL"

        return round(score, 4), status, is_anomaly

    def save(self, filepath: str = None):
        if filepath is None:
            filepath = os.path.join(MODEL_DIR, "anomaly_detector.joblib")
        data = {
            "model": self.model,
            "preprocessor": self.preprocessor,
            "contamination": self.contamination,
            "is_trained": self.is_trained
        }
        joblib.dump(data, filepath)

    def load(self, filepath: str = None) -> bool:
        if filepath is None:
            filepath = os.path.join(MODEL_DIR, "anomaly_detector.joblib")
        if not os.path.exists(filepath):
            return False
        try:
            data = joblib.load(filepath)
            self.model = data["model"]
            self.preprocessor = data["preprocessor"]
            self.contamination = data["contamination"]
            self.is_trained = data["is_trained"]
            return True
        except Exception as e:
            print(f"Error loading anomaly detector: {e}")
            return False
