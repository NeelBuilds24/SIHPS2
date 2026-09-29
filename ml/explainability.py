import numpy as np
import pandas as pd
from typing import Dict, Any, List
from ml.feature_extraction import FEATURE_COLUMNS, extract_features_from_dict

try:
    import shap
    SHAP_AVAILABLE = True
except ImportError:
    SHAP_AVAILABLE = False

class AlertExplainer:
    """Generates explainable evidence for alerts using SHAP and rule-based fallback logic."""
    def __init__(self, classifier_model=None, preprocessor=None):
        self.model = classifier_model
        self.preprocessor = preprocessor
        self.explainer = None
        
        if SHAP_AVAILABLE and self.model is not None:
            try:
                self.explainer = shap.TreeExplainer(self.model)
            except Exception:
                self.explainer = None

    def explain_alert(
        self,
        flow_dict: Dict[str, Any],
        predicted_class: str,
        ml_confidence: float,
        anomaly_score: float,
        risk_score: float
    ) -> Dict[str, Any]:
        """Generate human-readable evidence points and feature contributions."""
        feats = extract_features_from_dict(flow_dict)
        evidence_points = []
        shap_values_dict = {}

        # Try SHAP explanation if available
        if self.explainer is not None and self.preprocessor is not None:
            try:
                df_single = pd.DataFrame([feats])
                X_scaled = self.preprocessor.transform(df_single)
                shap_vals = self.explainer.shap_values(X_scaled)

                # Handle multi-class shap output array shape
                if isinstance(shap_vals, list):
                    vals = shap_vals[0][0]
                elif len(shap_vals.shape) == 3:
                    vals = shap_vals[0, :, 0]
                else:
                    vals = shap_vals[0]

                for col, val in zip(FEATURE_COLUMNS, vals):
                    shap_values_dict[col] = round(float(val), 4)
            except Exception:
                pass

        # Rule-based evidence points (guaranteed & highly readable)
        if predicted_class == "SYN_FLOOD":
            if feats["syn_count"] > 100:
                evidence_points.append(f"Abnormally high SYN packet count: {feats['syn_count']:.0f}")
            if feats["ack_syn_ratio"] < 0.2:
                evidence_points.append(f"Low ACK/SYN ratio ({feats['ack_syn_ratio']:.3f}) indicating incomplete handshakes")
            if feats["source_diversity"] > 10.0:
                evidence_points.append(f"High source IP diversity ({feats['source_diversity']:.1f}) targeting single destination")
            if feats["packets_per_sec"] > 1000:
                evidence_points.append(f"Surge in packets/sec: {feats['packets_per_sec']:.0f} pkts/s")

        elif predicted_class == "UDP_FLOOD":
            if feats["packets_per_sec"] > 2000:
                evidence_points.append(f"Extreme UDP packet rate: {feats['packets_per_sec']:.0f} pkts/s")
            if feats["bytes_per_sec"] > 1000000:
                evidence_points.append(f"High UDP bandwidth consumption: {feats['bytes_per_sec']/1024/1024:.2f} MB/s")
            if feats["dest_concentration"] > 0.8:
                evidence_points.append(f"High destination concentration ({feats['dest_concentration']*100:.0f}%)")

        elif predicted_class == "DNS_TUNNEL":
            if feats["domain_entropy"] > 3.5:
                evidence_points.append(f"High domain entropy ({feats['domain_entropy']:.2f}) indicating encoded payload")
            if feats["domain_length"] > 30:
                evidence_points.append(f"Unusually long DNS query string ({feats['domain_length']:.0f} chars)")
            if feats["subdomain_depth"] >= 3:
                evidence_points.append(f"Deep subdomain nesting depth: {feats['subdomain_depth']:.0f} levels")
            if feats["dns_tunnel_score"] > 60:
                evidence_points.append(f"High overall DNS Tunnel Score: {feats['dns_tunnel_score']:.1f}/100")

        elif predicted_class == "DGA":
            if feats["dga_score"] > 60:
                evidence_points.append(f"High DGA algorithm Score: {feats['dga_score']:.1f}/100")
            if feats["consonant_vowel_ratio"] > 3.0:
                evidence_points.append(f"Abnormal consonant-to-vowel ratio ({feats['consonant_vowel_ratio']:.2f})")
            if feats["digit_ratio"] > 0.25:
                evidence_points.append(f"Elevated digit-to-character ratio ({feats['digit_ratio']*100:.0f}%)")

        elif predicted_class == "C2_BEACON":
            if feats["c2_beacon_score"] > 70:
                evidence_points.append(f"High C2 Beacon Score: {feats['c2_beacon_score']:.1f}/100")
            if feats["inter_arrival_std"] < 0.05:
                evidence_points.append(f"Near-zero inter-arrival time variance (std = {feats['inter_arrival_std']:.4f}s)")
            if feats["periodicity_score"] > 80:
                evidence_points.append(f"High temporal periodicity ({feats['periodicity_score']:.0f}/100)")

        elif predicted_class == "SLOWLORIS":
            if feats["flow_duration"] > 100:
                evidence_points.append(f"Abnormally persistent flow duration ({feats['flow_duration']:.0f} seconds)")
            if feats["packets"] < 30:
                evidence_points.append(f"Very low packet count ({feats['packets']:.0f} pkts) relative to connection lifetime")

        if not evidence_points:
            evidence_points.append("Flow parameters closely align with learned malicious statistical profile.")

        return {
            "threat": predicted_class,
            "evidence": evidence_points,
            "ml_confidence_pct": round(ml_confidence * 100.0, 1),
            "anomaly_score": round(anomaly_score, 2),
            "risk_score": round(risk_score, 1),
            "top_shap_features": shap_values_dict
        }
