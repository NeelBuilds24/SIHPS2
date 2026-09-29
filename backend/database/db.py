import os
import json
import sqlite3
import time
from typing import Dict, Any, List, Optional

DB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data")
DB_PATH = os.path.join(DB_DIR, "sentinelgraph.db")

def get_db_connection():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initialize SQLite tables for alerts, attack_chains, baseline, and audit_blocks."""
    conn = get_db_connection()
    cursor = conn.cursor()

    # Alerts table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        alert_id TEXT UNIQUE NOT NULL,
        timestamp REAL NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        src_port INTEGER,
        dst_port INTEGER,
        protocol TEXT,
        threat TEXT NOT NULL,
        confidence REAL NOT NULL,
        anomaly_score REAL NOT NULL,
        risk_score REAL NOT NULL,
        severity TEXT NOT NULL,
        attack_chain_id TEXT,
        evidence_json TEXT,
        raw_flow_json TEXT
    );
    """)

    # Attack Chains table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS attack_chains (
        chain_id TEXT PRIMARY KEY,
        created_at REAL NOT NULL,
        last_updated REAL NOT NULL,
        src_ip TEXT NOT NULL,
        dst_ip TEXT NOT NULL,
        event_count INTEGER NOT NULL,
        max_risk_score REAL NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        threat_sequence_json TEXT,
        events_json TEXT
    );
    """)

    # Baseline table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS baseline_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp REAL NOT NULL,
        metric TEXT NOT NULL,
        baseline_value REAL NOT NULL,
        observed_value REAL NOT NULL,
        deviation_pct REAL NOT NULL,
        status TEXT NOT NULL
    );
    """)

    conn.commit()
    conn.close()

class DatabaseService:
    def __init__(self):
        init_db()

    def insert_alert(self, alert_data: Dict[str, Any]):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO alerts (
                alert_id, timestamp, src_ip, dst_ip, src_port, dst_port,
                protocol, threat, confidence, anomaly_score, risk_score,
                severity, attack_chain_id, evidence_json, raw_flow_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            alert_data["alert_id"],
            alert_data.get("timestamp", time.time()),
            alert_data["src_ip"],
            alert_data["dst_ip"],
            alert_data.get("src_port", 0),
            alert_data.get("dst_port", 0),
            alert_data.get("protocol", "TCP"),
            alert_data["threat"],
            alert_data["confidence"],
            alert_data["anomaly_score"],
            alert_data["risk_score"],
            alert_data["severity"],
            alert_data.get("attack_chain_id", ""),
            json.dumps(alert_data.get("evidence", {})),
            json.dumps(alert_data.get("raw_flow", {}))
        ))
        conn.commit()
        conn.close()

    def get_alerts(self, limit: int = 100, severity_filter: Optional[str] = None) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        if severity_filter:
            cursor.execute("SELECT * FROM alerts WHERE severity = ? ORDER BY id DESC LIMIT ?", (severity_filter, limit))
        else:
            cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
        rows = cursor.fetchall()
        conn.close()
        
        alerts = []
        for r in rows:
            d = dict(r)
            d["evidence"] = json.loads(d["evidence_json"]) if d.get("evidence_json") else {}
            d["raw_flow"] = json.loads(d["raw_flow_json"]) if d.get("raw_flow_json") else {}
            alerts.append(d)
        return alerts

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM alerts WHERE alert_id = ?", (alert_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["evidence"] = json.loads(d["evidence_json"]) if d.get("evidence_json") else {}
        d["raw_flow"] = json.loads(d["raw_flow_json"]) if d.get("raw_flow_json") else {}
        return d

    def upsert_attack_chain(self, chain_data: Dict[str, Any]):
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO attack_chains (
                chain_id, created_at, last_updated, src_ip, dst_ip,
                event_count, max_risk_score, severity, status,
                threat_sequence_json, events_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            chain_data["chain_id"],
            chain_data["created_at"],
            chain_data["last_updated"],
            chain_data["src_ip"],
            chain_data["dst_ip"],
            chain_data["event_count"],
            chain_data["max_risk_score"],
            chain_data["severity"],
            chain_data["status"],
            json.dumps(chain_data.get("threat_sequence", [])),
            json.dumps(chain_data.get("events", []))
        ))
        conn.commit()
        conn.close()

    def get_attack_chains(self) -> List[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attack_chains ORDER BY last_updated DESC")
        rows = cursor.fetchall()
        conn.close()
        chains = []
        for r in rows:
            d = dict(r)
            d["threat_sequence"] = json.loads(d["threat_sequence_json"]) if d.get("threat_sequence_json") else []
            d["events"] = json.loads(d["events_json"]) if d.get("events_json") else []
            chains.append(d)
        return chains

    def get_attack_chain_by_id(self, chain_id: str) -> Optional[Dict[str, Any]]:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM attack_chains WHERE chain_id = ?", (chain_id,))
        row = cursor.fetchone()
        conn.close()
        if not row:
            return None
        d = dict(row)
        d["threat_sequence"] = json.loads(d["threat_sequence_json"]) if d.get("threat_sequence_json") else []
        d["events"] = json.loads(d["events_json"]) if d.get("events_json") else []
        return d
