import time
import uuid
from typing import Dict, Any, List, Optional

from ml.feature_extraction import extract_features_from_dict
from ml.classifier import ThreatClassifier
from ml.anomaly_detector import AnomalyDetector
from ml.threat_scoring import HybridRiskScorer
from ml.correlation import CorrelationEngine
from ml.attack_graph import AttackGraphBuilder
from ml.stage_mapper import map_threat_to_stage
from ml.forecaster import MarkovThreatForecaster
from ml.adaptive_baseline import AdaptiveBaseline
from ml.explainability import AlertExplainer
from blockchain.audit_chain import AuditChain
from backend.database.db import DatabaseService

class SentinelGraphEngine:
    """Master Security Intelligence Service coordinating all passive SentinelGraph modules."""
    _instance = None

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = SentinelGraphEngine()
        return cls._instance

    def __init__(self):
        print("Initializing SentinelGraph Core Engine...")
        self.classifier = ThreatClassifier()
        self.classifier.load()

        self.anomaly_detector = AnomalyDetector()
        self.anomaly_detector.load()

        self.risk_scorer = HybridRiskScorer()
        self.correlation_engine = CorrelationEngine()
        self.attack_graph_builder = AttackGraphBuilder()
        self.forecaster = MarkovThreatForecaster()
        self.forecaster.load()

        self.adaptive_baseline = AdaptiveBaseline()
        self.explainer = AlertExplainer(self.classifier.model, self.classifier.preprocessor)
        self.audit_chain = AuditChain()
        self.db = DatabaseService()

        self.alert_counter = 1

    def process_flow(self, flow_raw: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute full end-to-end passive analysis pipeline for an ingested flow record.
        Strictly passive: NO network packets or socket requests are ever transmitted.
        """
        timestamp = float(flow_raw.get("timestamp", time.time()))
        src_ip = str(flow_raw.get("src_ip", "192.168.1.100"))
        dst_ip = str(flow_raw.get("dst_ip", "10.0.100.50"))
        protocol = str(flow_raw.get("protocol", "TCP"))

        # 1. Feature Extraction
        feats = extract_features_from_dict(flow_raw)

        # 2. Supervised Threat Classification
        predicted_class, ml_conf, prob_dict = self.classifier.predict_single(flow_raw)

        # 3. Anomaly Detection
        anomaly_score, anomaly_status, is_anomaly = self.anomaly_detector.predict_single(flow_raw)

        # 4. Hybrid Risk Scoring
        risk_score, severity, risk_breakdown = self.risk_scorer.compute_risk(
            predicted_class, ml_conf, anomaly_score, flow_raw
        )

        # 5. Explainable AI Evidence
        evidence = self.explainer.explain_alert(
            flow_raw, predicted_class, ml_conf, anomaly_score, risk_score
        )

        # 6. Attack Chain Correlation
        alert_id = f"ALERT-{self.alert_counter:05d}"
        self.alert_counter += 1

        alert_meta = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "threat": predicted_class,
            "risk_score": risk_score
        }
        attack_chain_id = self.correlation_engine.process_event(alert_meta)

        # Update chain in DB if created
        if attack_chain_id:
            chain_obj = self.correlation_engine.get_chain(attack_chain_id)
            if chain_obj:
                self.db.upsert_attack_chain(chain_obj)

        # 7. Attack Graph update
        alert_graph_data = alert_meta.copy()
        alert_graph_data["attack_chain_id"] = attack_chain_id
        self.attack_graph_builder.add_flow_event(alert_graph_data)

        # 8. Stage Mapping & Forecasting
        kill_chain_stage = map_threat_to_stage(predicted_class)
        forecast_data = self.forecaster.predict_next_stage(predicted_class)

        # 9. Adaptive Baseline
        is_benign = (predicted_class == "BENIGN" and risk_score < 30.0)
        self.adaptive_baseline.update_baseline(flow_raw, is_benign=is_benign)
        baseline_deviation = self.adaptive_baseline.compare_observation(flow_raw)

        # 10. Blockchain Audit Block Creation
        audit_block = self.audit_chain.add_evidence(
            alert_id=alert_id,
            attack_chain_id=attack_chain_id or "CHAIN-NONE",
            evidence_data={
                "alert_id": alert_id,
                "timestamp": timestamp,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "threat": predicted_class,
                "confidence": ml_conf,
                "risk_score": risk_score,
                "severity": severity,
                "evidence_summary": evidence["evidence"]
            }
        )

        # 11. Database Persistence
        alert_record = {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": flow_raw.get("src_port", 0),
            "dst_port": flow_raw.get("dst_port", 0),
            "protocol": protocol,
            "threat": predicted_class,
            "confidence": ml_conf,
            "anomaly_score": anomaly_score,
            "risk_score": risk_score,
            "severity": severity,
            "attack_chain_id": attack_chain_id,
            "evidence": evidence,
            "raw_flow": flow_raw
        }
        self.db.insert_alert(alert_record)

        # Final structured response
        return {
            "alert_id": alert_id,
            "timestamp": timestamp,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "protocol": protocol,
            "threat": predicted_class,
            "confidence": round(ml_conf, 4),
            "probabilities": prob_dict,
            "anomaly_score": round(anomaly_score, 4),
            "anomaly_status": anomaly_status,
            "risk_score": round(risk_score, 2),
            "severity": severity,
            "risk_breakdown": risk_breakdown,
            "attack_chain_id": attack_chain_id or "CHAIN-NONE",
            "kill_chain_stage": kill_chain_stage,
            "evidence": evidence,
            "forecast": forecast_data,
            "baseline_deviation": baseline_deviation,
            "audit_block_index": audit_block.index,
            "dataset_type": flow_raw.get("dataset_type", "SYNTHETIC / LAB DATA")
        }
