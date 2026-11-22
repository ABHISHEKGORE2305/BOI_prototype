# train.py
#
# Train the LightGBM malware classifier on the Drebin-215 dataset.
#
#   python -m nexus_sec.train [--max-fpr 0.01]
#
# Writes models/malware_model.pkl (model bundle), models/feature_names.json
# and models/metrics.json.
#
# - The raw dataset contains many exact duplicate rows (over half of it).
#   They are removed before splitting, otherwise the same samples land in
#   both train and test sets and the reported metrics are inflated.
# - Data is split train / validation / test. Probabilities are calibrated
#   (isotonic) on validation, and the decision threshold is the lowest one
#   whose validation false-positive rate stays within --max-fpr.
# - Drebin has no timestamps, so a temporal split isn't possible; use
#   `python -m nexus_sec.evaluate` on newer labelled samples to measure
#   how the model ages.

import argparse
import hashlib
import json
import logging
import os
import warnings
from datetime import datetime
from datetime import timezone

import joblib
import lightgbm
import numpy as np
import pandas as pd
import shap
from lightgbm import LGBMClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.model_selection import train_test_split

from nexus_sec import config
from nexus_sec.evaluation import choose_threshold
from nexus_sec.evaluation import classification_metrics
from nexus_sec.evaluation import ranking_metrics

logger = logging.getLogger("nexus_sec.train")

DEFAULT_DATASET = os.path.join(
    config.BASE_DIR,
    "datasets",
    "drebin-215-dataset-5560malware-9476-benign.csv"
)

LABEL_COLUMN = "class"
MALWARE_LABEL = "S"

GLOBAL_IMPORTANCE_TOP = 30

# SHAP warns on every call that LightGBM output is now a list; handled below
warnings.filterwarnings("ignore", message="LightGBM binary classifier with TreeExplainer")


def load_dataset(path):
    # A handful of cells contain "?" (unknown); LightGBM handles NaN natively
    df = pd.read_csv(path, na_values="?")

    raw_rows = len(df)
    df = df.drop_duplicates()
    unique_rows = len(df)

    # Drop feature vectors that appear with both labels
    feature_columns = [c for c in df.columns if c != LABEL_COLUMN]
    label_counts = (
        df.groupby(feature_columns, dropna=False)[LABEL_COLUMN]
        .transform("nunique")
    )
    df = df[label_counts == 1]
    conflicting = unique_rows - len(df)

    logger.info(
        "Loaded %d rows: %d unique, %d dropped for conflicting labels -> %d samples",
        raw_rows,
        unique_rows,
        conflicting,
        len(df)
    )

    stats = {
        "raw_rows": raw_rows,
        "unique_rows": unique_rows,
        "conflicting_rows_dropped": conflicting,
        "samples": len(df),
    }

    X = df[feature_columns].apply(pd.to_numeric)
    y = (df[LABEL_COLUMN] == MALWARE_LABEL).astype(int)

    return X, y, stats


def global_shap_importance(model, X, top=GLOBAL_IMPORTANCE_TOP):
    values = shap.TreeExplainer(model).shap_values(X)
    if isinstance(values, list):
        values = values[1]
    values = np.asarray(values)
    if values.ndim == 3:
        values = values[:, :, 1]

    mean_abs = np.abs(values).mean(axis=0)
    order = np.argsort(mean_abs)[::-1][:top]

    return [
        {"feature": X.columns[i], "importance": round(float(mean_abs[i]), 4)}
        for i in order
    ]


def model_version(model, threshold):
    # Content hash: retraining on the same data with the same seed gives the
    # same version, so cached scan results stay valid
    digest = hashlib.sha256(model.booster_.model_to_string().encode())
    digest.update(f"{threshold:.6f}".encode())
    return f"lgbm-{digest.hexdigest()[:12]}"


def train(dataset_path, out_dir, test_size, val_size, max_fpr, seed):
    X, y, stats = load_dataset(dataset_path)

    X_rest, X_test, y_rest, y_test = train_test_split(
        X, y, test_size=test_size, random_state=seed, stratify=y
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_rest, y_rest,
        test_size=val_size / (1 - test_size),
        random_state=seed,
        stratify=y_rest
    )

    model = LGBMClassifier(
        n_estimators=300,
        learning_rate=0.05,
        num_leaves=31,
        class_weight="balanced",
        random_state=seed,
        verbose=-1
    )
    model.fit(X_train, y_train)

    # class_weight="balanced" skews raw scores; isotonic regression maps
    # them back to real probabilities
    raw_val = model.predict_proba(X_val)[:, 1]
    calibrator = IsotonicRegression(out_of_bounds="clip", y_min=0.0, y_max=1.0)
    calibrator.fit(raw_val, y_val)

    threshold = choose_threshold(calibrator.predict(raw_val), y_val, max_fpr)

    raw_test = model.predict_proba(X_test)[:, 1]
    calibrated_test = calibrator.predict(raw_test)

    test_metrics = {
        **ranking_metrics(y_test, calibrated_test),
        "brier_uncalibrated": ranking_metrics(y_test, raw_test)["brier"],
        "at_threshold": classification_metrics(y_test, calibrated_test, threshold),
        "at_0_5": classification_metrics(y_test, calibrated_test, 0.5),
    }

    version = model_version(model, threshold)

    metrics = {
        "version": version,
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "dataset": os.path.basename(dataset_path),
        "lightgbm_version": lightgbm.__version__,
        "seed": seed,
        "data": {
            **stats,
            "train": len(X_train),
            "validation": len(X_val),
            "test": len(X_test),
            "malware_fraction": round(float(y.mean()), 4),
        },
        "max_fpr": max_fpr,
        "threshold": round(threshold, 6),
        "test_metrics": test_metrics,
        "global_importance": global_shap_importance(model, X_test),
        # Share of training samples where each feature fires (drift baseline)
        "feature_prevalence": {
            feature: round(float((X[feature] == 1).mean()), 6)
            for feature in X.columns
        },
    }

    bundle = {
        "model": model,
        "calibrator": calibrator,
        "threshold": threshold,
        "feature_names": list(X.columns),
        "version": version,
    }

    os.makedirs(out_dir, exist_ok=True)

    joblib.dump(bundle, os.path.join(out_dir, "malware_model.pkl"))

    with open(os.path.join(out_dir, "feature_names.json"), "w") as f:
        json.dump(list(X.columns), f)

    with open(os.path.join(out_dir, "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    at_threshold = test_metrics["at_threshold"]
    logger.info("Model %s", version)
    logger.info(
        "Test: ROC AUC %.4f | threshold %.4f (max FPR %.3f) -> "
        "precision %.4f, recall %.4f, FPR %.4f",
        test_metrics["roc_auc"],
        threshold,
        max_fpr,
        at_threshold["precision"],
        at_threshold["recall"],
        at_threshold["false_positive_rate"],
    )
    logger.info("Artifacts written to %s", out_dir)

    return metrics


def main():
    parser = argparse.ArgumentParser(description="Train the Nexus-Sec malware classifier")
    parser.add_argument("--dataset", default=DEFAULT_DATASET)
    parser.add_argument("--out-dir", default=config.MODEL_DIR)
    parser.add_argument("--test-size", type=float, default=0.2)
    parser.add_argument("--val-size", type=float, default=0.15)
    parser.add_argument(
        "--max-fpr",
        type=float,
        default=0.01,
        help="False-positive budget used to pick the decision threshold"
    )
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    train(args.dataset, args.out_dir, args.test_size, args.val_size, args.max_fpr, args.seed)


if __name__ == "__main__":
    main()
