"""
Network Packet Malware Classifier using CatBoost
==================================================
Custom preprocessing for 19-column malware dataset.
"""

import pandas as pd
import numpy as np
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, Tuple, Any

from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    confusion_matrix, roc_auc_score, roc_curve
)
from catboost import CatBoostClassifier, Pool

import matplotlib.pyplot as plt

# ---------------------
# CONFIG
# ---------------------
CSV_FILE = "malware analysis.csv"
MODEL_FILE = "catboost_packet_classifier.cbm"
METADATA_FILE = "model_metadata.json"
RANDOM_STATE = 42

HYPERPARAMS = {
    'iterations': 600,
    'learning_rate': 0.05,
    'depth': 8,
    'loss_function': 'Logloss',
    'eval_metric': 'AUC',
    'random_state': RANDOM_STATE,
    'verbose': 100,
    'task_type': 'GPU',
    'devices': '0'
}

_loaded_model: CatBoostClassifier = None


# =========================================================
# 1. LOAD DATA
# =========================================================
def load_data(filepath: str) -> pd.DataFrame:
    print(f"\n{'='*60}\nSTEP 1: Loading Dataset\n{'='*60}")
    try:
        df = pd.read_csv(filepath, header=None)
        print(f"✓ Loaded {len(df)} records | Shape: {df.shape}")
        print("✓ First row:", df.iloc[0].tolist())
        return df
    except Exception as e:
        raise Exception(f"Error loading data: {e}")


# =========================================================
# 2. PREPROCESS FOR YOUR 19-COLUMN DATASET
# =========================================================
def preprocess_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    print(f"\n{'='*60}\nSTEP 2: Preprocessing Malware Dataset\n{'='*60}")

    if df.shape[1] != 19:
        raise ValueError(f"Dataset must have 19 columns, found {df.shape[1]}")

    # Assign human-readable headers
    df.columns = [
        "duration",
        "protocol_type",
        "service",
        "flag",
        "src_bytes",
        "dst_bytes",
        "land",
        "wrong_fragment",
        "urgent",
        "hot",
        "num_failed_logins",
        "logged_in",
        "num_compromised",
        "root_shell",
        "su_attempted",
        "num_root",
        "num_file_creations",
        "num_shells",
        "label"
    ]

    print("✓ Assigned 19 custom feature names")

    # Convert labels to binary
    df["malicious"] = (df["label"] != "normal.").astype(int)
    df.drop("label", axis=1, inplace=True)
    print("✓ Converted labels: normal.=0, attack=1")

    # Categorical fields
    cat_cols = ["protocol_type", "service", "flag"]
    print("✓ Categorical features:", cat_cols)

    # One-hot encoding
    df = pd.get_dummies(df, columns=cat_cols, drop_first=True)
    print("✓ One-hot encoded categorical features")

    # Missing value handling
    if df.isnull().any().any():
        df.fillna(0, inplace=True)
        print("✓ Filled missing values")

    # Split X and y
    y = df["malicious"]
    X = df.drop("malicious", axis=1)

    print(f"✓ Total features: {len(X.columns)}")
    print("✓ First 10 features:", list(X.columns)[:10])
    print("\nClass distribution:")
    print(y.value_counts())

    return X, y


# =========================================================
# 3. TRAIN MODEL
# =========================================================
def train_model(X_train, y_train, X_test, y_test):
    print(f"\n{'='*60}\nSTEP 3: Training Model\n{'='*60}")

    params = HYPERPARAMS.copy()
    model = CatBoostClassifier(**params)

    train_pool = Pool(X_train, y_train)
    test_pool = Pool(X_test, y_test)

    start = time.time()
    try:
        model.fit(train_pool, eval_set=test_pool, use_best_model=True, plot=False)
    except Exception:
        print("⚠ GPU not available, switching to CPU")
        params["task_type"] = "CPU"
        params.pop("devices", None)
        model = CatBoostClassifier(**params)
        model.fit(train_pool, eval_set=test_pool, use_best_model=True, plot=False)

    train_time = time.time() - start
    print(f"✓ Training completed in {train_time:.2f} seconds")
    return model, train_time


# =========================================================
# 4. EVALUATION
# =========================================================
def evaluate_model(model, X_test, y_test):

    print(f"\n{'='*60}\nSTEP 4: Evaluation\n{'='*60}")

    pred = model.predict(X_test)
    prob = model.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": accuracy_score(y_test, pred),
        "precision": precision_score(y_test, pred, zero_division=0),
        "recall": recall_score(y_test, pred, zero_division=0),
        "f1_score": f1_score(y_test, pred, zero_division=0),
        "roc_auc": roc_auc_score(y_test, prob)
    }

    print("\nMetrics:")
    for k, v in metrics.items():
        print(f"{k}: {v:.4f}")

    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, pred))

    return metrics


# =========================================================
# 5. SAVE MODEL
# =========================================================
def save_model(model, feature_names, metrics, train_time):
    print(f"\n{'='*60}\nSTEP 5: Saving Model\n{'='*60}")

    model.save_model(MODEL_FILE)
    print("✓ Saved CatBoost model")

    metadata = {
        "model_type": "CatBoostClassifier",
        "created_at": datetime.now().isoformat(),
        "training_time": round(train_time, 2),
        "features": feature_names,
        "metrics": metrics
    }

    with open(METADATA_FILE, "w") as f:
        json.dump(metadata, f, indent=4)

    print("✓ Saved metadata")


# =========================================================
# 6. MAIN PIPELINE
# =========================================================
def main():
    print("\n" + "="*60)
    print(" NETWORK PACKET MALWARE CLASSIFIER ")
    print("="*60)

    df = load_data(CSV_FILE)
    X, y = preprocess_data(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
    )

    model, train_time = train_model(X_train, y_train, X_test, y_test)
    metrics = evaluate_model(model, X_test, y_test)
    save_model(model, list(X.columns), metrics, train_time)

    print("\n✓ Pipeline completed successfully.\n")


# =========================================================
# 7. PREDICTION FOR SINGLE PACKET
# =========================================================
import pandas as pd
from catboost import CatBoostClassifier

def predict_packet(packet_features: dict) -> dict:
    """
    Predict if a single network packet is malicious.
    
    Args:
        packet_features (dict): Features of one packet in 19-column format.
        
    Returns:
        dict: {
            "predicted_class": 0 or 1,
            "probability": float (class 1 probability),
            "prediction_label": "normal" or "malicious"
        }
    """
    global _loaded_model
    if _loaded_model is None:
        _loaded_model = CatBoostClassifier()
        _loaded_model.load_model(MODEL_FILE)

    # Convert dict to DataFrame
    df = pd.DataFrame([packet_features])

    # Align columns with model training features
    missing_cols = set(_loaded_model.feature_names_) - set(df.columns)
    for c in missing_cols:
        df[c] = 0  # fill missing columns with 0
    df = df[_loaded_model.feature_names_]  # reorder columns exactly

    # Predict
    prob = _loaded_model.predict_proba(df)[:, 1][0]  # probability of class 1
    pred = int(prob >= 0.5)
    label = "malicious" if pred == 1 else "normal"

    return {
        "predicted_class": pred,
        "probability": prob,
        "prediction_label": label
    }


if __name__ == "__main__":
    main()
