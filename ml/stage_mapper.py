from typing import Dict, List

STAGE_MAP = {
    "DGA": "Reconnaissance (Domain Generation)",
    "SLOWLORIS": "Resource Exhaustion / Delivery",
    "DNS_TUNNEL": "Exfiltration / Tunneling",
    "C2_BEACON": "Command & Control (Beaconing)",
    "SYN_FLOOD": "Denial of Service (SYN Flood)",
    "UDP_FLOOD": "Denial of Service (UDP Flood)",
    "BENIGN": "Normal Operation"
}

KILL_CHAIN_ORDER = [
    "Reconnaissance (Domain Generation)",
    "Resource Exhaustion / Delivery",
    "Command & Control (Beaconing)",
    "Exfiltration / Tunneling",
    "Denial of Service (SYN Flood)",
    "Denial of Service (UDP Flood)"
]

def map_threat_to_stage(threat: str) -> str:
    """Map a threat classification label to a Cyber Kill Chain stage."""
    return STAGE_MAP.get(threat, "Unknown Stage")
