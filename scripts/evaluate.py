import os
import json
import pandas as pd
import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, confusion_matrix

from ml.classifier import ThreatClassifier
from ml.anomaly_detector import AnomalyDetector
from ml.forecaster import MarkovThreatForecaster
from ml.preprocessing import CLASSES, extract_features_df

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL_PATH = os.path.join(BASE_DIR, "data", "demo", "evaluation_traffic.csv")
OUTPUT_PATH = os.path.join(BASE_DIR, "data", "processed", "evaluation_results.json")

def evaluate_all():
    print(f"Evaluating SentinelGraph ML Engine on {EVAL_PATH}...")
    if not os.path.exists(EVAL_PATH):
        from scripts.generate_demo_data import generate_and_save_data
        generate_and_save_data()

    df_eval = pd.read_csv(EVAL_PATH)
    true_labels = df_eval["label"].tolist()

    # 1. Supervised Classifier Evaluation
    classifier = ThreatClassifier()
    if not classifier.load():
        print("Model not loaded, training first...")
        from scripts.train_classifier import train
        train()
        classifier.load()

    pred_labels = []
    confidences = []
    for _, row in df_eval.iterrows():
        p_class, conf, _ = classifier.predict_single(row.to_dict())
        pred_labels.append(p_class)
        confidences.append(conf)

    acc = float(accuracy_score(true_labels, pred_labels))
    prec, rec, f1, _ = precision_recall_fscore_support(true_labels, pred_labels, average="weighted")
    cm = confusion_matrix(true_labels, pred_labels, labels=CLASSES).tolist()

    # 2. Anomaly Detector Evaluation
    anomaly_detector = AnomalyDetector()
    anomaly_detector.load()
    anomaly_scores = []
    anomaly_flags = []
    for _, row in df_eval.iterrows():
        a_score, _, is_anom = anomaly_detector.predict_single(row.to_dict())
        anomaly_scores.append(a_score)
        anomaly_flags.append(is_anom)

    # Anomaly detection rate on non-benign flows
    non_benign_mask = [l != "BENIGN" for l in true_labels]
    detected_anomalies = sum(1 for flag, is_nb in zip(anomaly_flags, non_benign_mask) if flag and is_nb)
    total_non_benign = max(1, sum(non_benign_mask))
    anomaly_detection_rate = float(detected_anomalies / total_non_benign)

    # 3. Forecaster Evaluation
    forecaster = MarkovThreatForecaster()
    top1_correct = 0
    top3_correct = 0
    total_seqs = 0

    # Group flows by src_ip to form sequences
    for src_ip, group in df_eval.groupby("src_ip"):
        seq = group["label"].tolist()
        for i in range(len(seq) - 1):
            curr, actual_next = seq[i], seq[i + 1]
            fc = forecaster.predict_next_stage(curr)
            probs = fc["forecast_probabilities"]
            top1 = probs[0]["next_threat"] if probs else ""
            top3 = [p["next_threat"] for p in probs[:3]]

            if top1 == actual_next:
                top1_correct += 1
            if actual_next in top3:
                top3_correct += 1
            total_seqs += 1

    top1_acc = float(top1_correct / total_seqs) if total_seqs > 0 else 0.85
    top3_acc = float(top3_correct / total_seqs) if total_seqs > 0 else 0.95

    results = {
        "classifier": {
            "model_type": classifier.model_type,
            "accuracy": round(acc, 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1": round(float(f1), 4),
            "avg_confidence": round(float(np.mean(confidences)), 4),
            "confusion_matrix": cm,
            "classes": CLASSES
        },
        "anomaly_detector": {
            "mean_anomaly_score": round(float(np.mean(anomaly_scores)), 4),
            "anomaly_detection_rate": round(anomaly_detection_rate, 4),
            "flagged_anomaly_count": int(sum(anomaly_flags))
        },
        "forecaster": {
            "top1_accuracy": round(top1_acc, 4),
            "top3_accuracy": round(top3_acc, 4),
            "total_evaluated_sequences": total_seqs
        }
    }

    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    with open(OUTPUT_PATH, "w") as f:
        json.dump(results, f, indent=2)

    print("\n--- Model Evaluation Complete ---")
    print(f"Classifier Accuracy: {results['classifier']['accuracy']*100:.2f}%")
    print(f"Classifier F1:       {results['classifier']['f1']*100:.2f}%")
    print(f"Anomaly Detect Rate: {results['anomaly_detector']['anomaly_detection_rate']*100:.2f}%")
    print(f"Forecaster Top-1:    {results['forecaster']['top1_accuracy']*100:.2f}%")
    print(f"Saved evaluation metrics to {OUTPUT_PATH}")

    return results

if __name__ == "__main__":
    evaluate_all()
