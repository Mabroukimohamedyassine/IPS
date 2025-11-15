# Intrusion Prevention System (IPS) — Real-Time Packet Capture and ML-Based Filtering
A Python-based Intrusion Prevention System (IPS) that captures network packets, extracts features into a structured format, and classifies each packet as malicious or benign using a machine learning model.

This project uses NFQueue for packet interception and CatBoost for classification.

Table of Contents

Project Overview

Architecture

Features

Project Structure

Installation

Usage

Training the ML Model

Future Improvements

Project Overview

The IPS captures incoming packets in real-time, extracts relevant features, and uses a machine learning classifier to make decisions. It then accepts safe packets or drops malicious ones immediately.

Key advantages:

Lightweight, real-time packet processing

Payload-aware feature extraction

ML-based threat detection

Architecture
           ┌────────────┐        ┌──────────────┐        ┌───────────┐
Incoming → │ Packet      │  NFQ   │ transform.py │  ML    │ Decision  │
Packets    │ Capture     │ ────→  │ (DataFrame)  │ ────→ │ ACCEPT/DROP
           └────────────┘        └──────────────┘        └───────────┘


Step-by-Step Flow:

Packet Capture (NFQueue): Intercepts packets from the network in real-time.

Packet Transformation: transform.py converts packets into a Pandas DataFrame with structured features (protocol, payload stats, metadata).

ML Classification: CatBoost predicts whether a packet is malicious or benign.

Decision Enforcement: Safe packets are accepted, malicious packets are dropped.

Features

Real-time packet interception using NFQueue

Packet-to-DataFrame transformation for ML input

ML-based detection using CatBoost

Immediate packet DROP/ACCEPT decision

Modular and extendable design

Project Structure
IPS/
│
├── Capture/
│   └── nfqueue_runner.py        # Real-time packet interception
│
├── Preprocessing/
│   └── transform.py             # Converts packet → pandas DataFrame
│
├── ML/
│   ├── dataset.csv              # Synthetic or real dataset
│   ├── train_model.py           # CatBoost training pipeline
│   └── model.cbm                # Saved trained model
│
├── README.md                    # Project documentation
└── requirements.txt             # Python dependencies

Installation

Clone the repository:

git clone https://github.com/yourusername/IPS.git
cd IPS


Create a virtual environment and install dependencies:

python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
pip install -r requirements.txt


Set up NFQueue (requires root privileges):

sudo iptables -I INPUT -j NFQUEUE --queue-num 0

Usage

Start the NFQueue runner:

python Capture/nfqueue_runner.py


Each captured packet will be transformed and classified automatically.

Decisions (ACCEPT/DROP) are applied in real-time.

Training the ML Model

CatBoost is used because it handles mixed numerical and categorical data, missing values, and small datasets efficiently.

To train a new model:

python ML/train_model.py


This script will:

Load the dataset (dataset.csv)

Preprocess features

Train the CatBoost model

Save the model as model.cbm

Future Improvements

Integrate anomaly detection alongside CatBoost

Add logging and alert dashboard

Extend with protocol-specific features

Optional integration with Suricata or other IDS systems
