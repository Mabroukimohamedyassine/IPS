"""
Network Packet Malware Classifier using CatBoost
==================================================
Production-ready script for training and deploying a CatBoost classifier
to detect malicious network packets based on packet features.

Author: Cleaned version
Python: 3.9+
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

# Configuration
CSV_FILE = "synthetic_packet_dataset.csv"
MODEL_FILE = "catboost_packet_classifier.cbm"
METADATA_FILE = "model_metadata.json"
RANDOM_STATE = 42

# Hyperparameters
HYPERPARAMS = {
    'iterations': 600,
    'learning_rate': 0.05,
    'depth': 8,
    'loss_function': 'Logloss',
    'eval_metric': 'AUC',
    'random_state': RANDOM_STATE,
    'verbose': 100,
    'task_type': 'GPU',  # fallback to CPU if GPU unavailable
    'devices': '0'
}

_loaded_model: CatBoostClassifier = None  # Lazy loaded model


def load_data(filepath: str) -> pd.DataFrame:
    """Load CSV dataset into pandas DataFrame."""
    print(f"\n{'='*60}\nSTEP 1: Loading Dataset\n{'='*60}")
    try:
        df = pd.read_csv(filepath)
        print(f"✓ Loaded {len(df)} records | Shape: {df.shape}")
        print(f"Columns: {list(df.columns)}")
        return df
    except FileNotFoundError:
        raise FileNotFoundError(f"CSV file not found: {filepath}")
    except Exception as e:
        raise Exception(f"Error loading data: {str(e)}")


def preprocess_data(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series]:
    """Preprocess dataset: remove payload, generate labels, handle missing."""
    print(f"\n{'='*60}\nSTEP 2: Preprocessing Data\n{'='*60}")
    df = df.copy()

    if 'payload_bytes' in df.columns:
        df.drop('payload_bytes', axis=1, inplace=True)
        print("✓ Removed 'payload_bytes' column")

    if 'malicious' not in df.columns:
        print("⚠ 'malicious' column missing. Generating labels...")
        df['malicious'] = (
            (df.get('has_shellcode_pattern', 0) == 1) |
            (df.get('has_suspicious_strings', 0) == 1) |
            (df.get('entropy', 0) > 6) |
            (df.get('payload_len', 0) > 150)
        ).astype(int)
        print("✓ Generated 'malicious' labels")
    else:
        print("✓ Found existing 'malicious' column")

    if df.isnull().any().any():
        print("⚠ Missing values found. Filling with 0")
        df.fillna(0, inplace=True)
    else:
        print("✓ No missing values detected")

    y = df['malicious']
    X = df.drop('malicious', axis=1)

    class_dist = y.value_counts()
    print(f"\nClass Distribution:")
    print(f"  Benign (0): {class_dist.get(0,0)} ({class_dist.get(0,0)/len(y)*100:.1f}%)")
    print(f"  Malicious (1): {class_dist.get(1,0)} ({class_dist.get(1,0)/len(y)*100:.1f}%)")
    print(f"Feature columns ({len(X.columns)}): {list(X.columns)}")

    return X, y


def train_model(X_train: pd.DataFrame, y_train: pd.Series,
                X_test: pd.DataFrame, y_test: pd.Series) -> Tuple[CatBoostClassifier, float]:
    """Train CatBoost classifier with GPU/CPU fallback."""
    print(f"\n{'='*60}\nSTEP 3: Training CatBoost Classifier\n{'='*60}")
    print("Hyperparameters (partial):")
    for k, v in HYPERPARAMS.items():
        if k not in ['verbose', 'devices']:
            print(f"  {k}: {v}")

    train_pool = Pool(X_train, y_train)
    test_pool = Pool(X_test, y_test)

    params = HYPERPARAMS.copy()
    model = CatBoostClassifier(**params)

    start_time = time.time()
    try:
        model.fit(train_pool, eval_set=test_pool, use_best_model=True, plot=False)
    except Exception as e:
        if 'GPU' in str(e) or 'CUDA' in str(e):
            print("⚠ GPU training failed. Falling back to CPU...")
            params['task_type'] = 'CPU'
            params.pop('devices', None)
            model = CatBoostClassifier(**params)
            model.fit(train_pool, eval_set=test_pool, use_best_model=True, plot=False)
        else:
            raise e

    training_time = time.time() - start_time
    print(f"✓ Training completed in {training_time:.2f} seconds")
    return model, training_time


def evaluate_model(model: CatBoostClassifier, X_test: pd.DataFrame,
                   y_test: pd.Series) -> Dict[str, float]:
    """Evaluate model and generate plots."""
    print(f"\n{'='*60}\nSTEP 4: Model Evaluation\n{'='*60}")
    y_pred = model.predict(X_test)
    y_pred_proba = model.predict_proba(X_test)[:, 1]

    metrics = {
        'accuracy': accuracy_score(y_test, y_pred),
        'precision': precision_score(y_test, y_pred, zero_division=0),
        'recall': recall_score(y_test, y_pred, zero_division=0),
        'f1_score': f1_score(y_test, y_pred, zero_division=0),
        'roc_auc': roc_auc_score(y_test, y_pred_proba)
    }

    print("\nPerformance Metrics:")
    for k, v in metrics.items():
        print(f"  {k.capitalize()}: {v:.4f}")

    cm = confusion_matrix(y_test, y_pred)
    print(f"\nConfusion Matrix:\n{cm}")

    feature_importance = pd.DataFrame({
        'feature': X_test.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    print(f"\nTop 10 Features:")
    print(feature_importance.head(10))

    _plot_evaluation(y_test, y_pred, y_pred_proba, cm, feature_importance)
    return metrics


def _plot_evaluation(y_test, y_pred, y_pred_proba, cm, feature_importance):
    """Generate evaluation plots."""
    fig, axes = plt.subplots(1, 3, figsize=(18, 5))

    # Confusion Matrix
    ax = axes[0]
    im = ax.imshow(cm, interpolation='nearest', cmap='Blues')
    ax.set_title('Confusion Matrix')
    ax.set_ylabel('True')
    ax.set_xlabel('Predicted')
    for i in range(2):
        for j in range(2):
            ax.text(j, i, str(cm[i, j]), ha='center', va='center', color="white" if cm[i,j] > cm.max()/2 else "black")
    ax.set_xticks([0,1]); ax.set_yticks([0,1])
    ax.set_xticklabels(['Benign','Malicious'])
    ax.set_yticklabels(['Benign','Malicious'])
    plt.colorbar(im, ax=ax)

    # ROC Curve
    ax = axes[1]
    fpr, tpr, _ = roc_curve(y_test, y_pred_proba)
    roc_auc = roc_auc_score(y_test, y_pred_proba)
    ax.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (AUC={roc_auc:.3f})')
    ax.plot([0,1], [0,1], color='navy', lw=2, linestyle='--')
    ax.set_xlim([0.0,1.0]); ax.set_ylim([0.0,1.05])
    ax.set_xlabel('False Positive Rate'); ax.set_ylabel('True Positive Rate')
    ax.set_title('ROC Curve'); ax.legend(loc='lower right'); ax.grid(alpha=0.3)

    # Feature Importance
    ax = axes[2]
    top_features = feature_importance.head(10)
    ax.barh(top_features['feature'], top_features['importance'], color='steelblue')
    ax.invert_yaxis(); ax.set_xlabel('Importance'); ax.set_title('Top 10 Features')
    ax.grid(axis='x', alpha=0.3)

    plt.tight_layout()
    plt.savefig('model_evaluation.png', dpi=300, bbox_inches='tight')
    print("✓ Saved evaluation plots to 'model_evaluation.png'")
    plt.close()


def save_model(model: CatBoostClassifier, feature_names: list,
               metrics: Dict[str,float], training_time: float):
    """Save trained model and metadata."""
    print(f"\n{'='*60}\nSTEP 5: Saving Model & Metadata\n{'='*60}")
    model.save_model(MODEL_FILE)
    print(f"✓ Model saved to '{MODEL_FILE}'")

    metadata = {
        'model_type': 'CatBoostClassifier',
        'version': '1.0',
        'created_at': datetime.now().isoformat(),
        'training_time_seconds': round(training_time,2),
        'features': feature_names,
        'num_features': len(feature_names),
        'hyperparameters': {k:v for k,v in HYPERPARAMS.items() if k not in ['verbose','devices']},
        'evaluation_metrics': {k: round(v,4) for k,v in metrics.items()}
    }

    with open(METADATA_FILE,'w') as f:
        json.dump(metadata, f, indent=2)
    print(f"✓ Metadata saved to '{METADATA_FILE}'")


def predict_packet(features_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Predict if packet is malicious using lazy-loaded model."""
    global _loaded_model
    if _loaded_model is None:
        if not Path(MODEL_FILE).exists():
            raise FileNotFoundError(f"Model file not found: {MODEL_FILE}")
        _loaded_model = CatBoostClassifier()
        _loaded_model.load_model(MODEL_FILE)

    df = pd.DataFrame([features_dict])
    # Ensure all features exist
    for col in _loaded_model.feature_names_:
        if col not in df.columns:
            df[col] = 0

    proba = float(_loaded_model.predict_proba(df)[0,1])
    pred = int(proba > 0.5)

    return {
        'predicted_class': pred,
        'probability': proba,
        'prediction_label': 'MALICIOUS' if pred==1 else 'BENIGN'
    }


def demo_prediction(model: CatBoostClassifier, X_test: pd.DataFrame):
    """Demonstrate predictions on sample test packets."""
    print(f"\n{'='*60}\nSTEP 6: Prediction Demo\n{'='*60}")
    samples = X_test.sample(min(3, len(X_test)), random_state=RANDOM_STATE)
    for idx, (_, row) in enumerate(samples.iterrows(),1):
        features = row.to_dict()
        result = predict_packet(features)
        print(f"Sample {idx}: entropy={features.get('entropy',0):.2f}, "
              f"payload_len={features.get('payload_len',0)}, "
              f"has_shellcode={features.get('has_shellcode_pattern',0)}")
        print(f"→ Prediction: {result['prediction_label']}, Confidence: {result['probability']:.1%}\n")


def main():
    print("\n" + "="*60)
    print(" NETWORK PACKET MALWARE CLASSIFIER")
    print(" Powered by CatBoost")
    print("="*60)
    try:
        df = load_data(CSV_FILE)
        X, y = preprocess_data(df)
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=RANDOM_STATE, stratify=y
        )
        print(f"\nTrain: {len(X_train)} | Test: {len(X_test)}")

        model, training_time = train_model(X_train, y_train, X_test, y_test)
        metrics = evaluate_model(model, X_test, y_test)
        save_model(model, list(X.columns), metrics, training_time)
        demo_prediction(model, X_test)

        print(f"\n{'='*60}\n✓ PIPELINE COMPLETED SUCCESSFULLY\n{'='*60}\n")
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        raise


if __name__ == "__main__":
    main()
