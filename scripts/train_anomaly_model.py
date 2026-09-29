import os
import pandas as pd
from ml.anomaly_detector import AnomalyDetector

def train():
    data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "demo", "synthetic_traffic.csv")
    if not os.path.exists(data_path):
        from scripts.generate_demo_data import generate_and_save_data
        generate_and_save_data()

    print(f"Loading data from {data_path}...")
    df = pd.read_csv(data_path)

    print("Training Isolation Forest Anomaly Detector...")
    detector = AnomalyDetector(contamination=0.1)
    res = detector.train(df)

    print("\n--- Anomaly Detector Results ---")
    print(f"Trained Samples: {res['trained_samples']}")
    print(f"Contamination:   {res['contamination']}")
    print(f"Mean Decision Score: {res['mean_score']}")

if __name__ == "__main__":
    train()
