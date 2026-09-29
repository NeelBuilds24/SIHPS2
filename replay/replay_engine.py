import os
import time
import threading
import pandas as pd
from typing import Dict, Any, List, Optional
from backend.services.detection_service import SentinelGraphEngine

DEMO_CSV = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "demo", "evaluation_traffic.csv")

class ReplayEngine:
    """Simulates real-time chronological stream replay of historical/synthetic unidirectional flows."""
    def __init__(self):
        self.status = "STOPPED"  # STOPPED, RUNNING, PAUSED
        self.speed_multiplier = 1.0
        self.current_index = 0
        self.total_flows = 0
        self.processed_flows = 0
        self.df: Optional[pd.DataFrame] = None
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()
        self.load_dataset()

    def load_dataset(self, csv_path: str = DEMO_CSV):
        if os.path.exists(csv_path):
            self.df = pd.read_csv(csv_path)
            self.total_flows = len(self.df)
        else:
            from scripts.generate_demo_data import generate_dataset
            self.df = generate_dataset(300)
            self.total_flows = len(self.df)

    def start(self, speed_multiplier: float = 1.0):
        self.speed_multiplier = max(0.1, float(speed_multiplier))
        if self.status == "RUNNING":
            return
        
        if self.status == "STOPPED":
            self.current_index = 0
            self.processed_flows = 0

        self.status = "RUNNING"
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def pause(self):
        if self.status == "RUNNING":
            self.status = "PAUSED"

    def stop(self):
        self.status = "STOPPED"
        self._stop_event.set()
        self.current_index = 0

    def _run_loop(self):
        engine = SentinelGraphEngine.get_instance()
        
        while not self._stop_event.is_set() and self.status in ["RUNNING", "PAUSED"]:
            if self.status == "PAUSED":
                time.sleep(0.5)
                continue

            if self.df is None or self.current_index >= len(self.df):
                self.status = "STOPPED"
                break

            row_dict = self.df.iloc[self.current_index].to_dict()
            row_dict["timestamp"] = time.time()
            
            # Process flow through SentinelGraph master engine
            engine.process_flow(row_dict)

            self.current_index += 1
            self.processed_flows += 1

            # Sleep duration scaled by speed multiplier
            sleep_time = max(0.05, 0.5 / self.speed_multiplier)
            time.sleep(sleep_time)

    def get_status(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "speed_multiplier": self.speed_multiplier,
            "current_index": self.current_index,
            "total_flows": self.total_flows,
            "processed_flows": self.processed_flows,
            "progress_pct": round((self.processed_flows / max(1, self.total_flows)) * 100.0, 1)
        }
