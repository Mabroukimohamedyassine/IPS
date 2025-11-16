#!/usr/bin/env python3
"""
NFQueue Packet Filter with ML Decision
Uses Transform.py to extract features in 19-column format
Uses ml.py (CatBoost model) to classify packets
"""

import logging
from netfilterqueue import NetfilterQueue
from scapy.all import IP
import pandas as pd

# Import updated Transform function
from Transform import packet_to_ml_format

# Import ML prediction function (should take a DataFrame row or dict)
from ml import predict_packet

# Configuration
QUEUE_NUM = 0

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)


def process_packet(nfpacket):
    """
    NFQueue callback function.
    Converts packet -> features -> ML classifier -> drop/accept decision.
    """

    # 1. Convert NFQUEUE raw payload to Scapy packet
    packet_bytes = nfpacket.get_payload()
    try:
        scapy_pkt = IP(packet_bytes)
    except Exception as e:
        logger.error(f"Error parsing packet: {e}")
        nfpacket.accept()
        return

    # 2. Extract packet features into a dataframe (19-column format)
    try:
        df_packet = packet_to_ml_format(scapy_pkt)
    except Exception as e:
        logger.error(f"Feature extraction failed: {e}")
        nfpacket.accept()
        return

    if df_packet is None or df_packet.empty:
        logger.warning("Empty feature set, accepting packet.")
        nfpacket.accept()
        return

    # Convert the single-row DF to dict for predict_packet
    features = df_packet.iloc[0].to_dict()

    # 3. ML prediction
    try:
        result = predict_packet(features)
    except Exception as e:
        logger.error(f"ML prediction failed: {e}")
        nfpacket.accept()
        return

    pred = result.get("predicted_class", 0)
    prob = result.get("probability", 0.0)
    label = result.get("prediction_label", "normal")

    logger.info(f"ML Decision → {label} ({prob:.2%})")

    # 4. Apply firewall decision
    if pred == 1:
        logger.warning("⇢ PACKET DROPPED (ML flagged as malicious)")
        nfpacket.drop()
    else:
        logger.info("⇢ Packet accepted")
        nfpacket.accept()


def main():
    logger.info("=" * 60)
    logger.info("      NFQUEUE + CatBoost ML Packet Filter")
    logger.info(f"      Queue Number: {QUEUE_NUM}")
    logger.info("=" * 60)

    nfqueue = NetfilterQueue()
    nfqueue.bind(QUEUE_NUM, process_packet)

    logger.info("Listening for packets...")
    try:
        nfqueue.run()
    except KeyboardInterrupt:
        logger.info("Shutting down...")
    finally:
        nfqueue.unbind()


if __name__ == "__main__":
    main()
