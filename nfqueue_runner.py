#!/usr/bin/env python3
"""
NFQueue Packet Filter with ML Decision
Uses T.py to extract features
Uses ml.py (CatBoost model) to classify packets
"""

import logging
from netfilterqueue import NetfilterQueue
from scapy.all import IP

# Import T function
from Transform import packet_to_dataframe_enhanced

# Import ML prediction function
from ml import predict_packet

# Configuration
QUEUE_NUM = 0

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
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

    # 2. Extract packet features into a dataframe
    df_packet = packet_to_dataframe_enhanced(
        scapy_pkt,
        include_advanced_features=True
    )

    if df_packet is None or df_packet.empty:
        logger.warning("Empty feature set, accepting packet.")
        nfpacket.accept()
        return

    # Convert the single-row DF to a dict
    features = df_packet.iloc[0].to_dict()

    # 3. ML decision
    try:
        result = predict_packet(features)
    except Exception as e:
        logger.error(f"ML prediction failed: {e}")
        nfpacket.accept()
        return

    pred = result["predicted_class"]
    prob = result["probability"]
    label = result["prediction_label"]

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
