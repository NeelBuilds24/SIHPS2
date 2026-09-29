# SentinelGraph: AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

**Smart India Hackathon (SIH) 2026 — Problem Statement 26145**

* **Organization:** National Technical Research Organisation (NTRO)
* **Category:** Software
* **Theme:** Blockchain & Cybersecurity
* **Project Name:** SentinelGraph
* **Tagline:** *Detect the threat. Understand its evolution. Forecast what may come next.*

---

## 1. Problem Statement & Core Concept

Critical-infrastructure operators monitor gateway/peering links using passive mirroring or hardware data diodes. In this enclave:
* **The system CANNOT send traffic back**
* **The system CANNOT probe or scan source/destination IPs**
* **The system CANNOT complete TCP handshakes or initiate requests**
* **The system CANNOT push active mitigation commands**
* **The system CANNOT depend on bidirectional communications**

SentinelGraph makes all security decisions using **only passive packet captures, flow records, and derived metadata**.

### Strict Unidirectional Enforcement Rule
```text
ONE-WAY IP TRAFFIC
        ↓
PASSIVE INGESTION
        ↓
FLOW / PACKET FEATURE EXTRACTION
        ↓
AI/ML THREAT DETECTION & ANOMALY ANALYSIS
        ↓
HYBRID RISK SCORING
        ↓
MULTI-STAGE ATTACK CORRELATION
        ↓
INTERACTIVE ATTACK GRAPH
        ↓
EXPLAINABLE EVIDENCE (SHAP)
        ↓
PROBABILISTIC NEXT-STAGE FORECAST
        ↓
TAMPER-EVIDENT AUDIT LEDGER (BLOCKCHAIN)
        ↓
SOC VISUAL DASHBOARD
```

The system operates strictly as:
$$\text{OBSERVE} \longrightarrow \text{ANALYZE} \longrightarrow \text{REPORT}$$

**Never:**
$$\text{OBSERVE} \longrightarrow \text{ATTACK/PROBE} \longrightarrow \text{RESPOND}$$

---

## 2. Threat Scenarios Supported

SentinelGraph passively detects six major cyber threat vectors:

1. **SYN Flood:** Detects high SYN rates, low ACK/SYN ratios, and high source diversity without completing handshakes.
2. **UDP Flood:** Identifies massive UDP packet/byte surges, packet size anomalies, and target concentration.
3. **Slowloris / Slow HTTP:** Detects persistent long-lived connections, low packet counts, and high inter-arrival times.
4. **DNS Tunnelling:** Computes a **DNS Tunnel Score (0–100)** derived from query string length, Shannon entropy, subdomain depth, and query frequency.
5. **DGA (Domain Generation Algorithm):** Classifies domains as `NORMAL`, `SUSPICIOUS`, or `POTENTIAL_DGA` based on consonant/vowel ratios, digit density, and entropy.
6. **C2 / Beaconing:** Calculates a **Beaconing Score (0–100)** derived from inter-arrival time standard deviation, periodicity, uniform packet sizes, and destination consistency.

---

## 3. System Architecture

```text
                 PRODUCTION NETWORK
                         │
                  ONE-WAY TRAFFIC
                         │
                         ▼
                ┌─────────────────┐
                │ Passive Sensor  │
                │ / Data Diode    │
                └────────┬────────┘
                         │
                         ▼
                MONITORING ENCLAVE
                         │
         ┌───────────────┴───────────────┐
         ▼                               ▼
   Flow Extraction                Packet Metadata
         │                               │
         └───────────────┬───────────────┘
                         ▼
                     ML ENGINE
           (XGBoost + Isolation Forest)
                         │
                         ▼
                   ALERT ENGINE
                         │
                         ▼
                 STREAMLIT DASHBOARD
```

---

## 4. Machine Learning & Intelligence Modules

* **Supervised Classifier (`ml/classifier.py`):** Multi-class XGBoost model (with Random Forest and LightGBM fallbacks) predicting `BENIGN`, `SYN_FLOOD`, `UDP_FLOOD`, `SLOWLORIS`, `DNS_TUNNEL`, `DGA`, `C2_BEACON`.
* **Anomaly Detector (`ml/anomaly_detector.py`):** Isolation Forest trained on benign baseline traffic producing normalized anomaly scores (`0.0`–`1.0`) and status labels (`NORMAL`, `SUSPICIOUS`, `ANOMALOUS`, `HIGHLY ANOMALOUS`).
* **Hybrid Risk Scorer (`ml/threat_scoring.py`):** Configurable 0–100 risk score formula:
  $$\text{Risk Score} = 40\% \text{ (ML Conf)} + 30\% \text{ (Anomaly)} + 20\% \text{ (Behavioral)} + 10\% \text{ (Temporal)}$$
  * `0–29`: LOW | `30–59`: MEDIUM | `60–79`: HIGH | `80–100`: CRITICAL
* **Attack Correlation (`ml/correlation.py`):** Groups related passive flows by source/destination IPs into multi-stage attack chains (`CHAIN-00001`).
* **Attack Graph (`ml/attack_graph.py`):** NetworkX topology graph visualized interactively via Plotly.
* **Threat Forecasting (`ml/forecaster.py`):** Lightweight Markov-chain stage forecaster estimating possible next attacker behavior.
  * *Labeled:* **Probabilistic Forecast — Not a Guaranteed Prediction**
* **Adaptive Baseline (`ml/adaptive_baseline.py`):** Poisoning-resistant rolling baseline learning normal volume/rates exclusively from benign traffic.
* **Explainable AI (`ml/explainability.py`):** SHAP feature attribution with deterministic rule-based fallback evidence.
* **Blockchain Audit Ledger (`blockchain/audit_chain.py`):** Permissioned SHA-256 cryptographic hash chain verifying evidence integrity.
  * *Explaining clearly:* **Blockchain provides tamper-evident evidence integrity; it does not perform detection or prediction.**

---

## 5. Quick Start & One-Command Demo

### Prerequisites
* Python 3.11+
* Installed packages in `requirements.txt`

### One-Command Launch
```bash
python run_demo.py
```

This single command will:
1. Generate synthetic traffic data (`data/demo/synthetic_traffic.csv`) if missing.
2. Train XGBoost, Isolation Forest, and Markov Forecaster models.
3. Launch **FastAPI Backend** on `http://localhost:8000`
4. Launch **Streamlit SOC Dashboard** on `http://localhost:8501`

---

## 6. Manual Execution

```bash
# 1. Generate Synthetic Traffic
python scripts/generate_demo_data.py

# 2. Train Models
python scripts/train_classifier.py
python scripts/train_anomaly_model.py
python scripts/train_forecaster.py

# 3. Evaluate Models
python scripts/evaluate.py

# 4. Run Backend Server
PYTHONPATH=. uvicorn backend.main:app --host 0.0.0.0 --port 8000

# 5. Run Frontend Dashboard
PYTHONPATH=. streamlit run frontend/app.py --server.port 8501
```

---

## 7. API Endpoints (FastAPI)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/health` | Enclave security health status |
| `POST` | `/predict` | Predict threat class & confidence |
| `POST` | `/anomaly` | Compute anomaly score & status |
| `POST` | `/analyze` | Execute full pipeline for flow |
| `POST` | `/upload` | Passive analysis of uploaded CSV |
| `GET` | `/alerts` | Retrieve alerts list |
| `GET` | `/alerts/{alert_id}` | Retrieve alert details & evidence |
| `GET` | `/attack-chains` | Retrieve correlated attack chains |
| `GET` | `/attack-graph/{id}` | Export Plotly attack graph JSON |
| `GET` | `/forecast/{id}` | Get Markov next-stage forecast |
| `GET` | `/baseline` | View adaptive normal baseline stats |
| `GET` | `/audit` | Get blockchain audit ledger |
| `GET` | `/audit/verify` | Verify hash chain integrity |
| `POST` | `/audit/tamper` | Simulate evidence tampering |
| `POST` | `/replay/start` | Start live flow stream replay |
| `POST` | `/replay/pause` | Pause flow stream replay |
| `POST` | `/replay/stop` | Stop & reset stream replay |
| `GET` | `/metrics` | Get empirical model evaluation metrics |

---

## 8. SIH 2026 Judge Demonstration Guide (3–5 Mins)

1. **Step 1 — Unidirectional Banner:** Open `http://localhost:8501`. Note the strict passive monitoring banner.
2. **Step 2 — Start Replay:** Go to **Live Stream & Replay** tab, click **▶ Start Replay**.
3. **Step 3 — Threat Detection:** Observe SYN Flood / UDP Flood alerts popping up with **CRITICAL** risk scores.
4. **Step 4 — Explainability:** Open **Threat Analysis & Alerts**, select an alert, inspect **WHY WAS THIS DETECTED?** evidence points.
5. **Step 5 — Attack Chain Correlation:** Go to **Attack Chains & Graph**, inspect `CHAIN-00001` containing multi-stage threat sequences.
6. **Step 6 — Attack Graph:** Interact with the Plotly NetworkX topology nodes & threat edges.
7. **Step 7 — Forecasting:** View **Threat Forecasting** Markov probability tree (e.g. `DNS Tunnelling -> C2 Beaconing 62%`).
8. **Step 8 — Audit Ledger:** Open **Audit Ledger (Blockchain)**, verify `AUDIT STATUS: VALID`.
9. **Step 9 — Tamper Test:** Click **⚠️ Simulate Tampering** and watch status flip from `VALID` to `INVALID`.

---

## 9. Important Limitations

1. **Synthetic Data:** Demonstration flows are synthetically generated for reproducible lab presentation.
2. **Probabilistic Forecasting:** Markov next-stage predictions represent probabilistic likelihoods, not guaranteed outcomes.
3. **Passive Monitoring Boundary:** Passive monitoring relies solely on observed flow metadata and cannot perform active endpoint validation.

---

## 10. License & Attribution

Designed and developed for **Smart India Hackathon 2026** under **Problem Statement 26145** (NTRO).
