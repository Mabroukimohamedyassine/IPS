# Network Packet Malware Classifier

A real-time network packet filter powered by machine learning. This project classifies network packets as normal or malicious using a CatBoost model, integrating NFQueue for packet interception and Scapy for packet parsing and feature extraction.

🚀 Overview

This system captures live network traffic, extracts relevant features from each packet, preprocesses them, and predicts whether the packet is malicious. Based on the prediction, it can automatically accept or drop packets, providing a smart, AI-driven firewall mechanism.

🛠 How It Works – Pipeline Steps
1. Packet Interception

Uses NFQueue to capture live packets on your system.

Requires administrator/root privileges.

2. Feature Extraction

Transform.py converts Scapy packets into a structured feature dictionary with 19 key fields, including:

protocol_type, service, flag, src_bytes, dst_bytes, land, etc.

Features are chosen for their relevance to malware detection.

3. Preprocessing

Categorical data (protocol, service, TCP flags) → one-hot encoded.

Numerical features → normalized and missing values handled.

Labels: "normal." = 0, others = 1 (“malicious”).

4. Prediction

Preprocessed features are passed to a CatBoost classifier loaded from disk.

Model outputs:

predicted_class (0 or 1)

prediction_label (normal / malicious)

probability (likelihood of being malicious)

5. Action

If malicious (predicted_class == 1) → packet is dropped.

Otherwise → packet is accepted.

📁 Files and Their Roles
File	Purpose
ml.py	Main ML pipeline: preprocesses data, trains and saves CatBoost model, evaluates metrics, predicts packet classes.
Transform.py	Converts raw Scapy packets into feature dictionaries suitable for ML.
Main NFQueue script	Integrates packet capture, ML predictions, and firewall actions in real-time.
⚙️ Key Variables & Parameters
Variable	Description
CSV_FILE	Path to the packet dataset used for training.
MODEL_FILE	Path to save/load the trained CatBoost model.
METADATA_FILE	Stores model metadata (features, metrics, training info).
RANDOM_STATE	Ensures reproducible train/test splits.
HYPERPARAMS	CatBoost parameters: iterations, learning rate, depth, GPU/CPU usage.
🧩 Model Features (Packet Attributes)

Core features include: protocol_type, service, flag, src_bytes, dst_bytes, land, etc.

Categorical features are one-hot encoded, e.g., protocol_type_tcp, service_http.

🤖 Why CatBoost for Malware Detection?

CatBoost is a gradient boosting library optimized for tabular data with categorical features.

Advantages:

Handles categorical features natively.

Works well on small and large datasets.

Fast training with GPU support.

Robust against overfitting with built-in regularization.

Application:

Network traffic is mostly tabular with many categorical fields (protocols, services, flags).

CatBoost can make accurate predictions without complex feature engineering, ideal for security and anomaly detection.

🧠 What is the “AI” Here?

Supervised Machine Learning:

Model learns from labeled packet data (“normal” vs “malicious”).

Generalizes to unseen traffic patterns.

Automates cybersecurity response.

Factors Affecting Predictions:

Packet features: length, protocol, TCP flags, port/service, fragmentation, login attempts, file creation, etc.

CatBoost hyperparameters: iterations, depth, learning rate.

Distribution and labeling of underlying dataset.

⚡ How to Run

Prepare the dataset

Place a properly formatted CSV file (19 columns) in the specified path.

Train the model

python ml.py


Preprocesses data, trains CatBoost, evaluates metrics, and saves the model.

Set up NFQueue

Configure your OS to forward packets to NFQueue (requires admin/root).

Run main script

Start the live packet filtering pipeline. Packets will be classified and acted upon in real-time.

📝 Summary Review

Uses categorical features like protocols, ports, and flags.

Employs supervised ML (CatBoost) to predict from labeled data.

Implements feature engineering on packet properties.

Automates firewall actions based on real-time ML predictions.
