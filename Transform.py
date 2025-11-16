import pandas as pd
import numpy as np
from scapy.all import IP, TCP, UDP, ICMP, Raw
from typing import Optional

# Map common ports to services (simplified)
PORT_SERVICE_MAP = {
    80: "http",
    443: "https",
    53: "dns",
    21: "ftp",
    22: "ssh",
    25: "smtp",
}

# Map TCP flags to simplified states (example, adapt as needed)
TCP_FLAG_MAP = {
    0: "OTH",  # no flags
    1: "FIN",
    2: "SYN",
    3: "SYN-ACK",
    4: "RST",
    16: "ACK",
    24: "PSH-ACK",
}

def packet_to_ml_format(packet):
    # Initialize raw feature dict
    features = {
        "duration": 0,
        "protocol_type": "other",
        "service": "other",
        "flag": "OTH",
        "src_bytes": 0,
        "dst_bytes": 0,
        "land": 0,
        "wrong_fragment": 0,
        "urgent": 0,
        "hot": 0,
        "num_failed_logins": 0,
        "logged_in": 0,
        "num_compromised": 0,
        "root_shell": 0,
        "su_attempted": 0,
        "num_root": 0,
        "num_file_creations": 0,
        "num_shells": 0,
        "label": "normal."
    }

    # Protocol type
    if packet.haslayer(TCP):
        features["protocol_type"] = "tcp"
        features["src_bytes"] = len(packet[TCP].payload) if packet.haslayer(Raw) else 0
        features["dst_bytes"] = 0
        # TCP flags
        tcp_flags = int(packet[TCP].flags)
        features["flag"] = TCP_FLAG_MAP.get(tcp_flags, "OTH")
    elif packet.haslayer(UDP):
        features["protocol_type"] = "udp"
        features["src_bytes"] = len(packet[UDP].payload) if packet.haslayer(Raw) else 0
        features["dst_bytes"] = 0
        features["flag"] = "OTH"
    elif packet.haslayer(ICMP):
        features["protocol_type"] = "icmp"
        features["src_bytes"] = len(packet[ICMP].payload) if packet.haslayer(Raw) else 0
        features["dst_bytes"] = 0
        features["flag"] = "OTH"

    # Service based on dst port
    dst_port = 0
    if packet.haslayer(TCP):
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        dst_port = packet[UDP].dport
    features["service"] = PORT_SERVICE_MAP.get(dst_port, "other")

    # Land check
    if packet.haslayer(IP):
        ip = packet[IP]
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport
            dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport
            features["land"] = int(ip.src == ip.dst and sport == dport)

    # Return DataFrame
    df = pd.DataFrame([features])

    # One-hot encode categorical fields to match ml.py format
    cat_cols = ["protocol_type", "service", "flag"]
    df = pd.get_dummies(df, columns=cat_cols, drop_first=True)

    return df
