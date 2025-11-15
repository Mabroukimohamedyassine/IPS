#!/bin/bash

# Flush previous rules
iptables -F

# Send all forwarded packets to NFQUEUE 0
iptables -I FORWARD -j NFQUEUE --queue-num 0

# Send incoming packets to NFQUEUE 0
iptables -I INPUT -j NFQUEUE --queue-num 0

echo "[*] iptables rules applied. Packets will be sent to NFQUEUE 0."
