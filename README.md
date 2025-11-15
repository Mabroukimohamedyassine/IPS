#Intrusion Prevention System (IPS) — Packet Capture and ML-Based Filtering

This project implements a real-time Intrusion Prevention System (IPS) capable of capturing network packets, transforming them into structured features, and classifying each packet as malicious or benign using a machine-learning model.

📌 Project Architecture
           ┌────────────┐          ┌──────────────┐          ┌───────────┐
Incoming → │ Packet      │  NFQ     │ transform.py │  Feature │ ML Model   │ → Decision
Packets    │ Capture     │ ─────→   │ (DataFrame)  │ ─────→   │ (CatBoost) │ → Accept/Drop
           └────────────┘          └──────────────┘          └───────────┘

🔹 1. Packet Capture (NFQueue)

A Python script hooks into iptables and forwards packets into an NFQueue.
Each packet is intercepted in real time and sent to the processing pipeline.

🔹 2. Packet Transformation

transform.py converts each raw packet into a structured Pandas DataFrame row, extracting relevant features such as:

Protocol (TCP/UDP/HTTP, etc.)

Payload statistics

Packet metadata (length, flags, etc.)

This produces a consistent format for the ML model.

🔹 3. Machine Learning Classification

Extracted features are passed to a trained CatBoostClassifier, which predicts whether the packet is malicious or benign.

🔹 4. Decision & Enforcement

Benign → ACCEPT (packet continues normally)

Malicious → DROP (packet is blocked immediately)

📁 Project Structure
IPS/
│
├── Capture/
│   ├── nfqueue_runner.py        # NFQueue packet interception
│
├── Preprocessing/
│   ├── transform.py             # Converts packet → pandas DataFrame
│
├── ML/
│   ├── dataset.csv              # Synthetic or real dataset
│   ├── train_model.py           # CatBoost training pipeline
│   ├── model.cbm                # Saved trained model
│
├── README.md                    # Documentation
└── requirements.txt             # Dependencies

⚙️ How It Works (Step‑By‑Step)
1️⃣ Redirect packets into NFQueue
sudo iptables -I INPUT -j NFQUEUE --queue-num 0

2️⃣ Python intercepts packets

nfqueue_runner.py receives packets in real time.

3️⃣ Packet transformation

transform.py converts each packet into a Pandas row containing structured features.

4️⃣ ML model classifies

The trained CatBoost model predicts:

0 = benign

1 = malicious

5️⃣ Packet is accepted or dropped
🧪 Training the ML Model

CatBoost is used because:

Handles numerical and categorical data

Fast training

Robust with small datasets

Handles missing values automatically

To train:

python ML/train_model.py


This script:
✔ Loads the dataset
✔ Preprocesses features
✔ Trains CatBoost
✔ Saves model.cbm

🛡️ Features

Real-time packet capture

Payload-aware feature extraction

CatBoost ML-based detection

Immediate DROP/ACCEPT enforcement

Modular architecture

🚀 Requirements

scapy

catboost

numpy

pandas

netfilterqueue

🔮 Future Improvements

Add anomaly detection models

Logging and alerting system

GUI dashboard

Integration with Suricata or other IDS for cross-validation
