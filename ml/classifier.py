import os
import joblib
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

try:
    import xgboost as xgb
    XGB_AVAILABLE = True
except ImportError:
    XGB_AVAILABLE = False

try:
    import lightgbm as lgb
    LGB_AVAILABLE = True
except ImportError:
    LGB_AVAILABLE = False

from ml.preprocessing import Preprocessor, CLASSES
from ml.feature_extraction import FEATURE_COLUMNS, extract_features_from_dict

MODEL_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "models")

class ThreatClassifier:
    """Supervised Threat Classifier supporting XGBoost, Random Forest, and LightGBM."""
    def __init__(self, model_type: str = "xgboost"):
        self.model_type = model_type.lower()
        self.preprocessor = Preprocessor()
        self.model = None
        self.is_trained = False

    def _init_model(self):
        if self.model_type == "xgboost" and XGB_AVAILABLE:
            self.model = xgb.XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                eval_metric="mlogloss"
            )
        elif self.model_type == "lightgbm" and LGB_AVAILABLE:
            self.model = lgb.LGBMClassifier(
                n_estimators=100,
                max_depth=6,
                random_state=42,
                verbosity=-1
            )
        else:
            self.model_type = "random_forest"
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42
            )

    def train(self, df: pd.DataFrame, label_col: str = "label") -> Dict[str, Any]:
        """Train classifier and preprocessor on training dataframe."""
        os.makedirs(MODEL_DIR, exist_ok=True)
        self._init_model()
        
        labels = df[label_col].tolist()
        X_scaled, y_encoded = self.preprocessor.fit_transform(df, labels)
        
        self.model.fit(X_scaled, y_encoded)
        self.is_trained = True
        
        # Calculate training evaluation metrics
        y_pred = self.model.predict(X_scaled)
        acc = accuracy_score(y_encoded, y_pred)
        precision, recall, f1, _ = precision_recall_fscore_support(y_encoded, y_pred, average="weighted")
        cm = confusion_matrix(y_encoded, y_pred).tolist()
        
        metrics = {
            "model_type": self.model_type,
            "accuracy": round(float(acc), 4),
            "precision": round(float(precision), 4),
            "recall": round(float(recall), 4),
            "f1": round(float(f1), 4),
            "confusion_matrix": cm,
            "classes": self.preprocessor.classes
        }
        
        self.save()
        return metrics

    def predict_single(self, flow_dict: Dict[str, Any]) -> Tuple[str, float, Dict[str, float]]:
        """Predict threat class, confidence score, and probability distribution for a single flow."""
        if not self.is_trained:
            if not self.load():
                return self._rule_based_fallback(flow_dict)

        feats_dict = extract_features_from_dict(flow_dict)
        df_single = pd.DataFrame([feats_dict])
        X_scaled = self.preprocessor.transform(df_single)
        
        probs = self.model.predict_proba(X_scaled)[0]
        top_idx = int(np.argmax(probs))
        classes_list = self.preprocessor.classes
        predicted_class = classes_list[top_idx]
        confidence = float(probs[top_idx])
        
        prob_dict = {cls_name: round(float(p), 4) for cls_name, p in zip(classes_list, probs)}
        return predicted_class, round(confidence, 4), prob_dict

    def _rule_based_fallback(self, flow_dict: Dict[str, Any]) -> Tuple[str, float, Dict[str, float]]:
        feats = extract_features_from_dict(flow_dict)
        classes_list = self.preprocessor.classes
        
        if feats["syn_count"] > 1000 and feats["ack_syn_ratio"] < 0.1:
            cls = "SYN_FLOOD"
            conf = 0.95
        elif feats["packets_per_sec"] > 2000 and flow_dict.get("protocol") == "UDP":
            cls = "UDP_FLOOD"
            conf = 0.92
        elif feats["dns_tunnel_score"] > 70.0:
            cls = "DNS_TUNNEL"
            conf = 0.91
        elif feats["dga_score"] > 65.0:
            cls = "DGA"
            conf = 0.88
        elif feats["c2_beacon_score"] > 75.0:
            cls = "C2_BEACON"
            conf = 0.87
        elif feats["flow_duration"] > 300 and feats["packets"] < 20:
            cls = "SLOWLORIS"
            conf = 0.85
        else:
            cls = "BENIGN"
            conf = 0.98
            
        prob_dict = {c: (conf if c == cls else round((1.0 - conf) / (len(classes_list) - 1), 4)) for c in classes_list}
        return cls, conf, prob_dict

    def save(self, filepath: str = None):
        if filepath is None:
            filepath = os.path.join(MODEL_DIR, f"threat_classifier_{self.model_type}.joblib")
        data = {
            "model_type": self.model_type,
            "model": self.model,
            "preprocessor": self.preprocessor,
            "is_trained": self.is_trained
        }
        joblib.dump(data, filepath)

    def load(self, filepath: str = None) -> bool:
        if filepath is None:
            filepath = os.path.join(MODEL_DIR, f"threat_classifier_{self.model_type}.joblib")
            if not os.path.exists(filepath):
                for alt in ["xgboost", "random_forest", "lightgbm"]:
                    alt_path = os.path.join(MODEL_DIR, f"threat_classifier_{alt}.joblib")
                    if os.path.exists(alt_path):
                        filepath = alt_path
                        break
        if not os.path.exists(filepath):
            return False
            
        try:
            data = joblib.load(filepath)
            self.model_type = data["model_type"]
            self.model = data["model"]
            self.preprocessor = data["preprocessor"]
            self.is_trained = data["is_trained"]
            return True
        except Exception as e:
            print(f"Error loading model: {e}")
            return False
