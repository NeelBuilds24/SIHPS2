import os
import pandas as pd
from ml.classifier import ThreatClassifier

def train():
    data_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "demo", "synthetic_traffic.csv")
    if not os.path.exists(data_path):
        from scripts.generate_demo_data import generate_and_save_data
        generate_and_save_data()
        
    print(f"Loading training data from {data_path}...")
    df = pd.read_csv(data_path)
    
    print("Training XGBoost Threat Classifier...")
    classifier = ThreatClassifier(model_type="xgboost")
    metrics = classifier.train(df)
    
    print("\n--- Training Results ---")
    print(f"Model Type: {metrics['model_type']}")
    print(f"Accuracy:   {metrics['accuracy'] * 100:.2f}%")
    print(f"Precision:  {metrics['precision'] * 100:.2f}%")
    print(f"Recall:     {metrics['recall'] * 100:.2f}%")
    print(f"F1 Score:   {metrics['f1'] * 100:.2f}%")

if __name__ == "__main__":
    train()
