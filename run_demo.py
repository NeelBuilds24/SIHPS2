#!/usr/bin/env python3
"""
SentinelGraph — One-Command Demo Launcher
NTRO Problem Statement 26145: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
"""

import os
import sys
import time
import subprocess

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")
sys.path.insert(0, BASE_DIR)

def print_banner():
    banner = """
======================================================================
  🛡️  SENTINELGRAPH — UNIDIRECTIONAL THREAT INTELLIGENCE ENCLAVE  🛡️
======================================================================
  Problem Statement: NTRO PS 26145 (Cybersecurity & Blockchain)
  Tagline: Detect the threat. Understand its evolution. Forecast what may come next.
  Security Rule: STRICT PASSIVE ONE-WAY MONITORED LINK | ZERO RETURN PATH
  Frontend: React 18 + Vite + TypeScript + Tailwind CSS + React Flow
  Backend:  FastAPI + XGBoost + Isolation Forest + Markov Chain
======================================================================
    """
    print(banner)

def verify_data_and_models():
    print("[1/3] Checking dataset and ML models...")
    eval_path = os.path.join(BASE_DIR, "data", "demo", "synthetic_traffic.csv")
    model_path = os.path.join(BASE_DIR, "models", "threat_classifier_xgboost.joblib")

    if not os.path.exists(eval_path):
        print(" -> Generating synthetic demo dataset...")
        from scripts.generate_demo_data import generate_and_save_data
        generate_and_save_data()

    if not os.path.exists(model_path):
        print(" -> Training ML models...")
        from scripts.train_classifier import train as train_clf
        from scripts.train_anomaly_model import train as train_anom
        from scripts.train_forecaster import train as train_fc
        from scripts.evaluate import evaluate_all
        train_clf()
        train_anom()
        train_fc()
        evaluate_all()
    print(" -> ML Models & Dataset Ready.")

def launch_services():
    print("[2/3] Starting SentinelGraph FastAPI Backend (Port 8000)...")
    env = os.environ.copy()
    env["PYTHONPATH"] = BASE_DIR

    backend_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"],
        cwd=BASE_DIR,
        env=env
    )
    time.sleep(2)

    print("[3/3] Starting SentinelGraph React + Vite SOC Frontend (Port 5173)...")
    frontend_proc = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=FRONTEND_DIR,
        env=env
    )

    print("\n======================================================================")
    print("  🚀 SentinelGraph Services Launched Successfully!")
    print("======================================================================")
    print("  🌐 React SOC Frontend:   http://localhost:5173")
    print("  ⚡ REST API:             http://localhost:8000")
    print("  📚 Swagger Docs:          http://localhost:8000/docs")
    print("  🔒 Security Status:       PASSIVE MIRROR ENCLAVE — ACTIVE DIODE ENFORCED")
    print("======================================================================\n")
    print("Press Ctrl+C to shutdown demo services.\n")

    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\nShutting down SentinelGraph demo services...")
        backend_proc.terminate()
        frontend_proc.terminate()
        sys.exit(0)

if __name__ == "__main__":
    print_banner()
    verify_data_and_models()
    launch_services()
