import math
import numpy as np
import pandas as pd
from typing import Dict, Any, List, Union


def calculate_shannon_entropy(text: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not text:
        return 0.0
    prob = [float(text.count(c)) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def calculate_dns_tunnel_score(
    domain_length: float,
    entropy: float,
    subdomain_depth: float,
    query_freq: float
) -> float:
    """
    Calculate DNS Tunnel Score (0 - 100) based on passive DNS metadata.
    High length + high entropy + deep subdomains + high query rate -> high score.
    """
    length_score = min(1.0, max(0.0, (domain_length - 15.0) / 45.0)) * 30.0
    entropy_score = min(1.0, max(0.0, (entropy - 2.5) / 2.5)) * 35.0
    depth_score = min(1.0, max(0.0, (subdomain_depth - 1.0) / 4.0)) * 20.0
    freq_score = min(1.0, max(0.0, (query_freq - 5.0) / 45.0)) * 15.0

    score = length_score + entropy_score + depth_score + freq_score
    return round(float(np.clip(score, 0.0, 100.0)), 2)


def calculate_dga_score(
    domain: str,
    entropy: float
) -> Dict[str, float]:
    """
    Calculate DGA likelihood metrics.
    Features: entropy, consonant/vowel ratio, digit ratio, length.
    """
    if not domain:
        return {
            "domain_entropy": 0.0,
            "consonant_vowel_ratio": 0.0,
            "digit_ratio": 0.0,
            "dga_score": 0.0
        }
    
    # Strip common TLDs for analysis
    parts = domain.split('.')
    core_name = parts[0] if parts else domain
    length = len(core_name)
    
    vowels = set("aeiou")
    consonants = set("bcdfghjklmnpqrstvwxyz")
    
    v_count = sum(1 for c in core_name.lower() if c in vowels)
    c_count = sum(1 for c in core_name.lower() if c in consonants)
    d_count = sum(1 for c in core_name if c.isdigit())
    
    cv_ratio = float(c_count) / (v_count + 1e-5)
    digit_ratio = float(d_count) / (length + 1e-5)
    
    # Score calculation
    e_part = min(1.0, max(0.0, (entropy - 3.0) / 2.0)) * 40.0
    cv_part = min(1.0, max(0.0, (cv_ratio - 2.5) / 5.0)) * 30.0
    digit_part = min(1.0, max(0.0, digit_ratio / 0.4)) * 30.0
    
    dga_score = round(float(np.clip(e_part + cv_part + digit_part, 0.0, 100.0)), 2)
    
    return {
        "domain_entropy": round(entropy, 3),
        "consonant_vowel_ratio": round(cv_ratio, 3),
        "digit_ratio": round(digit_ratio, 3),
        "dga_score": dga_score
    }


def calculate_beacon_score(
    inter_arrival_mean: float,
    inter_arrival_std: float,
    dest_consistency: float,
    packet_size_std: float
) -> float:
    """
    Calculate C2 Beaconing Score (0 - 100) based on periodicity and consistency.
    Low inter-arrival std + high dest consistency + low packet size std -> high score.
    """
    if inter_arrival_mean <= 0.001:
        return 0.0
    
    # Periodicity coefficient of variation (lower std/mean ratio -> higher periodicity)
    cov = inter_arrival_std / (inter_arrival_mean + 1e-5)
    periodicity = max(0.0, 1.0 - min(1.0, cov / 1.5)) * 45.0
    
    dest_part = min(1.0, max(0.0, dest_consistency)) * 35.0
    
    # Packet size consistency
    size_part = max(0.0, 1.0 - min(1.0, packet_size_std / 200.0)) * 20.0
    
    score = periodicity + dest_part + size_part
    return round(float(np.clip(score, 0.0, 100.0)), 2)


FEATURE_COLUMNS = [
    "flow_duration",
    "packets",
    "bytes",
    "packets_per_sec",
    "bytes_per_sec",
    "avg_pkt_size",
    "syn_count",
    "ack_count",
    "fin_count",
    "rst_count",
    "psh_count",
    "ack_syn_ratio",
    "syn_ratio",
    "domain_length",
    "subdomain_depth",
    "domain_entropy",
    "query_frequency",
    "dns_tunnel_score",
    "consonant_vowel_ratio",
    "digit_ratio",
    "dga_score",
    "inter_arrival_mean",
    "inter_arrival_std",
    "periodicity_score",
    "burstiness",
    "dest_concentration",
    "source_diversity",
    "c2_beacon_score"
]


def extract_features_from_dict(flow_raw: Dict[str, Any]) -> Dict[str, float]:
    """Extract standard numeric features from a single raw flow dict."""
    duration = max(0.0001, float(flow_raw.get("flow_duration", flow_raw.get("duration", 1.0))))
    pkts = max(1, float(flow_raw.get("packets", flow_raw.get("total_packets", 1))))
    n_bytes = max(1, float(flow_raw.get("bytes", flow_raw.get("total_bytes", 64))))
    
    pkts_sec = float(flow_raw.get("packets_per_sec", pkts / duration))
    bytes_sec = float(flow_raw.get("bytes_per_sec", n_bytes / duration))
    avg_pkt_size = float(flow_raw.get("avg_pkt_size", n_bytes / pkts))
    
    syn = float(flow_raw.get("syn_count", 0))
    ack = float(flow_raw.get("ack_count", 0))
    fin = float(flow_raw.get("fin_count", 0))
    rst = float(flow_raw.get("rst_count", 0))
    psh = float(flow_raw.get("psh_count", 0))
    
    ack_syn_ratio = float(ack / (syn + 1e-5))
    syn_ratio = float(syn / (pkts + 1e-5))
    
    # DNS Features
    domain_name = str(flow_raw.get("domain_name", flow_raw.get("dns_query", "")))
    domain_length = float(flow_raw.get("domain_length", len(domain_name)))
    subdomain_depth = float(flow_raw.get("subdomain_depth", max(0, domain_name.count('.') - 1)))
    domain_entropy = float(flow_raw.get("domain_entropy", calculate_shannon_entropy(domain_name)))
    query_frequency = float(flow_raw.get("query_frequency", 1.0))
    
    dns_tunnel_score = float(flow_raw.get(
        "dns_tunnel_score",
        calculate_dns_tunnel_score(domain_length, domain_entropy, subdomain_depth, query_frequency)
    ))
    
    dga_metrics = calculate_dga_score(domain_name, domain_entropy)
    cv_ratio = float(flow_raw.get("consonant_vowel_ratio", dga_metrics["consonant_vowel_ratio"]))
    digit_ratio = float(flow_raw.get("digit_ratio", dga_metrics["digit_ratio"]))
    dga_score = float(flow_raw.get("dga_score", dga_metrics["dga_score"]))
    
    # Temporal & Behavioral
    iat_mean = float(flow_raw.get("inter_arrival_mean", duration / max(1.0, pkts - 1)))
    iat_std = float(flow_raw.get("inter_arrival_std", 0.05))
    dest_conc = float(flow_raw.get("dest_concentration", 0.5))
    src_div = float(flow_raw.get("source_diversity", 1.0))
    pkt_size_std = float(flow_raw.get("pkt_size_std", 10.0))
    
    periodicity = float(flow_raw.get("periodicity_score", max(0.0, 100.0 - (iat_std / (iat_mean + 1e-5)) * 50.0)))
    burstiness = float(flow_raw.get("burstiness", pkts_sec / (pkts / duration + 1e-5)))
    
    c2_beacon_score = float(flow_raw.get(
        "c2_beacon_score",
        calculate_beacon_score(iat_mean, iat_std, dest_conc, pkt_size_std)
    ))

    extracted = {
        "flow_duration": round(duration, 4),
        "packets": round(pkts, 2),
        "bytes": round(n_bytes, 2),
        "packets_per_sec": round(pkts_sec, 2),
        "bytes_per_sec": round(bytes_sec, 2),
        "avg_pkt_size": round(avg_pkt_size, 2),
        "syn_count": round(syn, 2),
        "ack_count": round(ack, 2),
        "fin_count": round(fin, 2),
        "rst_count": round(rst, 2),
        "psh_count": round(psh, 2),
        "ack_syn_ratio": round(ack_syn_ratio, 4),
        "syn_ratio": round(syn_ratio, 4),
        "domain_length": round(domain_length, 2),
        "subdomain_depth": round(subdomain_depth, 2),
        "domain_entropy": round(domain_entropy, 4),
        "query_frequency": round(query_frequency, 2),
        "dns_tunnel_score": round(dns_tunnel_score, 2),
        "consonant_vowel_ratio": round(cv_ratio, 4),
        "digit_ratio": round(digit_ratio, 4),
        "dga_score": round(dga_score, 2),
        "inter_arrival_mean": round(iat_mean, 6),
        "inter_arrival_std": round(iat_std, 6),
        "periodicity_score": round(periodicity, 2),
        "burstiness": round(burstiness, 2),
        "dest_concentration": round(dest_conc, 4),
        "source_diversity": round(src_div, 2),
        "c2_beacon_score": round(c2_beacon_score, 2)
    }
    return extracted


def extract_features_df(df: pd.DataFrame) -> pd.DataFrame:
    """Process DataFrame and ensure all FEATURE_COLUMNS are correctly populated."""
    rows = []
    for _, row in df.iterrows():
        rows.append(extract_features_from_dict(row.to_dict()))
    res_df = pd.DataFrame(rows)
    # Ensure column order
    return res_df[FEATURE_COLUMNS]
