import os
import json
import io
import pandas as pd
from fastapi import APIRouter, HTTPException, UploadFile, File, BackgroundTasks
from typing import Dict, Any, List, Optional

from backend.schemas.models import (
    FlowInputSchema, PredictionResponseSchema, AnomalyResponseSchema,
    AnalysisResponseSchema, ReplayControlSchema, AuditTamperSchema
)
from backend.services.detection_service import SentinelGraphEngine
from replay.replay_engine import ReplayEngine

router = APIRouter()
replay_engine_instance = ReplayEngine()

@router.get("/health")
def health_check():
    return {
        "status": "HEALTHY",
        "system": "SentinelGraph Unidirectional Traffic Intelligence",
        "security_mode": "PASSIVE_ONE_WAY_ONLY",
        "active_listeners": "MONITORING_ENCLAVE_ACTIVE",
        "outbound_connections_permitted": False
    }

@router.post("/predict", response_model=PredictionResponseSchema)
def predict_threat(flow_input: FlowInputSchema):
    engine = SentinelGraphEngine.get_instance()
    threat, conf, probs = engine.classifier.predict_single(flow_input.model_dump())
    return {
        "threat": threat,
        "confidence": conf,
        "probabilities": probs
    }

@router.post("/anomaly", response_model=AnomalyResponseSchema)
def anomaly_check(flow_input: FlowInputSchema):
    engine = SentinelGraphEngine.get_instance()
    score, status, is_anom = engine.anomaly_detector.predict_single(flow_input.model_dump())
    return {
        "anomaly_score": score,
        "status": status,
        "is_anomaly": is_anom
    }

@router.post("/analyze", response_model=AnalysisResponseSchema)
def analyze_flow(flow_input: FlowInputSchema):
    engine = SentinelGraphEngine.get_instance()
    result = engine.process_flow(flow_input.model_dump())
    return result

@router.post("/upload")
async def upload_csv(file: UploadFile = File(...)):
    """Upload PCAP-derived or NetFlow CSV for offline passive threat analysis."""
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Only CSV flow files are supported.")
    
    contents = await file.read()
    try:
        df = pd.read_csv(io.BytesIO(contents))
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid CSV file format: {str(e)}")

    engine = SentinelGraphEngine.get_instance()
    analyzed_alerts = []
    
    for idx, row in df.iterrows():
        row_dict = row.to_dict()
        row_dict["dataset_type"] = f"USER UPLOADED: {file.filename}"
        res = engine.process_flow(row_dict)
        analyzed_alerts.append(res)

    return {
        "filename": file.filename,
        "total_rows_processed": len(df),
        "threats_detected": sum(1 for a in analyzed_alerts if a["threat"] != "BENIGN"),
        "alerts": analyzed_alerts[:20]  # Return top 20 alerts preview
    }

@router.get("/alerts")
def get_alerts(limit: int = 100, severity: Optional[str] = None):
    engine = SentinelGraphEngine.get_instance()
    alerts = engine.db.get_alerts(limit=limit, severity_filter=severity)
    return {"count": len(alerts), "alerts": alerts}

@router.get("/alerts/{alert_id}")
def get_alert_detail(alert_id: str):
    engine = SentinelGraphEngine.get_instance()
    alert = engine.db.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert ID not found.")
    return alert

@router.get("/attack-chains")
def get_attack_chains():
    engine = SentinelGraphEngine.get_instance()
    chains = engine.db.get_attack_chains()
    return {"count": len(chains), "attack_chains": chains}

@router.get("/attack-chains/{chain_id}")
def get_attack_chain_detail(chain_id: str):
    engine = SentinelGraphEngine.get_instance()
    chain = engine.db.get_attack_chain_by_id(chain_id)
    if not chain:
        raise HTTPException(status_code=404, detail="Attack chain ID not found.")
    return chain

@router.get("/attack-graph/{chain_id}")
def get_attack_graph_for_chain(chain_id: str):
    engine = SentinelGraphEngine.get_instance()
    fig = engine.attack_graph_builder.generate_plotly_figure()
    fig_json = json.loads(fig.to_json())
    return {"chain_id": chain_id, "graph_plotly_json": fig_json}

@router.get("/forecast/{chain_id}")
def get_forecast_for_chain(chain_id: str):
    engine = SentinelGraphEngine.get_instance()
    chain = engine.db.get_attack_chain_by_id(chain_id)
    curr_threat = "BENIGN"
    if chain and chain.get("threat_sequence"):
        curr_threat = chain["threat_sequence"][-1]
    
    forecast = engine.forecaster.predict_next_stage(curr_threat)
    return forecast

@router.get("/baseline")
def get_baseline_stats():
    engine = SentinelGraphEngine.get_instance()
    return engine.adaptive_baseline.baseline_stats

@router.get("/audit")
def get_audit_ledger():
    engine = SentinelGraphEngine.get_instance()
    valid, status_msg, details = engine.audit_chain.verify_chain()
    return {
        "status": status_msg,
        "is_valid": valid,
        "chain_length": len(engine.audit_chain.chain),
        "blocks": engine.audit_chain.to_list()
    }

@router.get("/audit/verify")
def verify_audit_chain():
    engine = SentinelGraphEngine.get_instance()
    valid, status_msg, details = engine.audit_chain.verify_chain()
    return {
        "is_valid": valid,
        "status": status_msg,
        "details": details
    }

@router.post("/audit/tamper")
def simulate_audit_tampering(payload: AuditTamperSchema):
    engine = SentinelGraphEngine.get_instance()
    success = engine.audit_chain.simulate_tampering(payload.block_index)
    valid, status_msg, _ = engine.audit_chain.verify_chain()
    return {
        "tampering_applied": success,
        "tampered_block_index": payload.block_index,
        "new_status": status_msg,
        "is_valid": valid
    }

@router.post("/replay/start")
def start_replay(payload: ReplayControlSchema):
    replay_engine_instance.start(payload.speed_multiplier)
    return replay_engine_instance.get_status()

@router.post("/replay/pause")
def pause_replay():
    replay_engine_instance.pause()
    return replay_engine_instance.get_status()

@router.post("/replay/stop")
def stop_replay():
    replay_engine_instance.stop()
    return replay_engine_instance.get_status()

@router.get("/replay/status")
def get_replay_status():
    return replay_engine_instance.get_status()

@router.get("/metrics")
def get_model_evaluation_metrics():
    eval_path = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "processed", "evaluation_results.json")
    if os.path.exists(eval_path):
        with open(eval_path, "r") as f:
            data = json.load(f)
        return data
    else:
        from scripts.evaluate import evaluate_all
        return evaluate_all()
