import os
import random
import time
import numpy as np
import pandas as pd
from typing import List, Dict, Any

# Ensure reproducible demo generation
np.random.seed(42)
random.seed(42)

DEMO_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "data", "demo")

BENIGN_DOMAINS = [
    "google.com", "github.com", "ntro.gov.in", "wikipedia.org",
    "stackoverflow.com", "amazon.in", "microsoft.com", "cdn.cloudflare.com"
]

DGA_CONSONANTS = "bcdfghjklmnpqrstvwxyz"
DGA_DIGITS = "0123456789"

def generate_random_ip(prefix: str = "192.168.1") -> str:
    return f"{prefix}.{random.randint(2, 254)}"

def generate_dga_domain() -> str:
    # High consonant & digit density
    c_part = "".join(random.choice(DGA_CONSONANTS) for _ in range(10))
    d_part = "".join(random.choice(DGA_DIGITS) for _ in range(5))
    tld = random.choice([".net", ".biz", ".info", ".cc", ".xyz", ".top"])
    return f"{c_part}{d_part}{tld}"

def generate_dns_tunnel_domain() -> str:
    hex_payload = "".join(random.choice("0123456789abcdef") for _ in range(40))
    sub2 = "".join(random.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(12))
    return f"{hex_payload}.{sub2}.exfil-tunnel-node.org"

def create_synthetic_flow(label: str, timestamp_offset: float) -> Dict[str, Any]:
    base_time = time.time() - 3600 + timestamp_offset
    target_ip = "10.0.100.50"
    
    flow = {
        "timestamp": base_time,
        "dataset_type": "SYNTHETIC / LAB DATA",
        "label": label,
        "dst_ip": target_ip,
        "dst_port": 80
    }
    
    if label == "BENIGN":
        flow["src_ip"] = generate_random_ip("10.0.1")
        flow["src_port"] = random.randint(1024, 65535)
        flow["protocol"] = random.choice(["TCP", "TCP", "UDP", "DNS"])
        flow["flow_duration"] = round(float(np.random.exponential(scale=2.0) + 0.5), 3)
        flow["packets"] = random.randint(15, 100)
        flow["bytes"] = flow["packets"] * random.randint(300, 1000)
        flow["syn_count"] = random.randint(1, 2)
        flow["ack_count"] = flow["syn_count"] + random.randint(10, 40)
        flow["fin_count"] = random.randint(1, 2)
        flow["rst_count"] = 0
        flow["psh_count"] = random.randint(2, 10)
        flow["domain_name"] = random.choice(BENIGN_DOMAINS) if flow["protocol"] in ["DNS", "UDP"] else ""
        flow["query_frequency"] = random.uniform(1.0, 5.0)
        flow["inter_arrival_mean"] = flow["flow_duration"] / max(1, flow["packets"])
        flow["inter_arrival_std"] = flow["inter_arrival_mean"] * random.uniform(0.8, 1.5)
        flow["dest_concentration"] = random.uniform(0.1, 0.3)
        flow["source_diversity"] = random.uniform(1.0, 3.0)

    elif label == "SYN_FLOOD":
        flow["src_ip"] = generate_random_ip(f"172.16.{random.randint(1, 20)}")
        flow["src_port"] = random.randint(1024, 65535)
        flow["protocol"] = "TCP"
        flow["dst_port"] = 80
        flow["flow_duration"] = round(random.uniform(0.5, 3.0), 3)
        flow["packets"] = random.randint(5000, 20000)
        flow["bytes"] = flow["packets"] * 64
        flow["syn_count"] = flow["packets"]
        flow["ack_count"] = 0
        flow["fin_count"] = 0
        flow["rst_count"] = 0
        flow["psh_count"] = 0
        flow["domain_name"] = ""
        flow["query_frequency"] = 0.0
        flow["inter_arrival_mean"] = flow["flow_duration"] / flow["packets"]
        flow["inter_arrival_std"] = flow["inter_arrival_mean"] * 0.1
        flow["dest_concentration"] = 0.98
        flow["source_diversity"] = random.uniform(100.0, 500.0)

    elif label == "UDP_FLOOD":
        flow["src_ip"] = generate_random_ip(f"198.51.{random.randint(1, 10)}")
        flow["src_port"] = random.randint(1024, 65535)
        flow["protocol"] = "UDP"
        flow["dst_port"] = 53
        flow["flow_duration"] = round(random.uniform(1.0, 5.0), 3)
        flow["packets"] = random.randint(8000, 30000)
        flow["bytes"] = flow["packets"] * 1200
        flow["syn_count"] = 0
        flow["ack_count"] = 0
        flow["fin_count"] = 0
        flow["rst_count"] = 0
        flow["psh_count"] = 0
        flow["domain_name"] = ""
        flow["query_frequency"] = 0.0
        flow["inter_arrival_mean"] = flow["flow_duration"] / flow["packets"]
        flow["inter_arrival_std"] = flow["inter_arrival_mean"] * 0.05
        flow["dest_concentration"] = 0.99
        flow["source_diversity"] = random.uniform(100.0, 400.0)

    elif label == "SLOWLORIS":
        flow["src_ip"] = "192.168.1.105"
        flow["src_port"] = random.randint(30000, 60000)
        flow["protocol"] = "TCP"
        flow["dst_port"] = 80
        flow["flow_duration"] = round(random.uniform(400.0, 1500.0), 3)
        flow["packets"] = random.randint(6, 18)
        flow["bytes"] = flow["packets"] * 75
        flow["syn_count"] = 1
        flow["ack_count"] = 2
        flow["fin_count"] = 0
        flow["rst_count"] = 0
        flow["psh_count"] = random.randint(2, 6)
        flow["domain_name"] = ""
        flow["query_frequency"] = 0.0
        flow["inter_arrival_mean"] = flow["flow_duration"] / flow["packets"]
        flow["inter_arrival_std"] = flow["inter_arrival_mean"] * 0.9
        flow["dest_concentration"] = 0.90
        flow["source_diversity"] = 1.0

    elif label == "DNS_TUNNEL":
        flow["src_ip"] = "192.168.1.120"
        flow["src_port"] = 53535
        flow["protocol"] = "DNS"
        flow["dst_port"] = 53
        flow["flow_duration"] = round(random.uniform(5.0, 20.0), 3)
        flow["packets"] = random.randint(80, 250)
        flow["bytes"] = flow["packets"] * 450
        flow["syn_count"] = 0
        flow["ack_count"] = 0
        flow["fin_count"] = 0
        flow["rst_count"] = 0
        flow["psh_count"] = 0
        flow["domain_name"] = generate_dns_tunnel_domain()
        flow["query_frequency"] = random.uniform(100.0, 350.0)
        flow["inter_arrival_mean"] = 0.08
        flow["inter_arrival_std"] = 0.01
        flow["dest_concentration"] = 0.95
        flow["source_diversity"] = 1.0

    elif label == "DGA":
        flow["src_ip"] = "192.168.1.140"
        flow["src_port"] = random.randint(40000, 60000)
        flow["protocol"] = "DNS"
        flow["dst_port"] = 53
        flow["flow_duration"] = round(random.uniform(0.1, 1.5), 3)
        flow["packets"] = random.randint(2, 5)
        flow["bytes"] = flow["packets"] * 100
        flow["syn_count"] = 0
        flow["ack_count"] = 0
        flow["fin_count"] = 0
        flow["rst_count"] = 0
        flow["psh_count"] = 0
        flow["domain_name"] = generate_dga_domain()
        flow["query_frequency"] = random.uniform(30.0, 120.0)
        flow["inter_arrival_mean"] = 0.15
        flow["inter_arrival_std"] = 0.05
        flow["dest_concentration"] = 0.80
        flow["source_diversity"] = 1.0

    elif label == "C2_BEACON":
        flow["src_ip"] = "192.168.1.150"
        flow["src_port"] = 4444
        flow["protocol"] = "TCP"
        flow["dst_ip"] = "185.220.101.5"
        flow["dst_port"] = 8443
        flow["flow_duration"] = 2.0
        flow["packets"] = 10
        flow["bytes"] = 800
        flow["syn_count"] = 1
        flow["ack_count"] = 8
        flow["fin_count"] = 1
        flow["rst_count"] = 0
        flow["psh_count"] = 3
        flow["domain_name"] = ""
        flow["query_frequency"] = 0.0
        flow["inter_arrival_mean"] = 5.0000
        flow["inter_arrival_std"] = 0.0005  # Near zero variance
        flow["dest_concentration"] = 1.0
        flow["source_diversity"] = 1.0

    return flow


def generate_dataset(num_samples: int = 1400) -> pd.DataFrame:
    labels = ["BENIGN"] * 600 + [
        "SYN_FLOOD", "UDP_FLOOD", "SLOWLORIS",
        "DNS_TUNNEL", "DGA", "C2_BEACON"
    ] * 133
    
    random.shuffle(labels)
    flows = []
    
    for idx, label in enumerate(labels[:num_samples]):
        offset = idx * 2.5
        flows.append(create_synthetic_flow(label, offset))
        
    df = pd.DataFrame(flows)
    return df


def generate_and_save_data():
    os.makedirs(DEMO_DIR, exist_ok=True)
    print("Generating SentinelGraph Synthetic Demo Dataset...")
    df_train = generate_dataset(num_samples=2100)
    train_path = os.path.join(DEMO_DIR, "synthetic_traffic.csv")
    df_train.to_csv(train_path, index=False)
    print(f"Saved training dataset with {len(df_train)} flows to {train_path}")
    
    df_eval = generate_dataset(num_samples=450)
    eval_path = os.path.join(DEMO_DIR, "evaluation_traffic.csv")
    df_eval.to_csv(eval_path, index=False)
    print(f"Saved evaluation dataset with {len(df_eval)} flows to {eval_path}")

if __name__ == "__main__":
    generate_and_save_data()
