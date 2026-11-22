# ml.py
#
# Model bundle loading, scoring, SHAP attribution and drift statistics.
#
# The worker loads the full bundle (LightGBM, calibrator, SHAP). The API
# only reads models/metrics.json so it doesn't need the ML stack.

import json
import os
import warnings
from dataclasses import dataclass
from functools import lru_cache

import numpy as np

from nexus_sec import config
from nexus_sec.features import load_feature_categories

TOP_K_FEATURES = 10

# SHAP warns on every call that LightGBM output is now a list; handled below
warnings.filterwarnings("ignore", message="LightGBM binary classifier with TreeExplainer")


class ModelNotTrainedError(RuntimeError):
    pass


@dataclass
class LoadedModel:
    model: object
    calibrator: object
    threshold: float
    feature_names: list
    version: str
    categories: dict
    explainer: object

    def malware_probability(self, feature_vector):
        raw = self.model.predict_proba(feature_vector)[:, 1]
        if self.calibrator is not None:
            raw = self.calibrator.predict(raw)
        return float(raw[0])

    def verdict(self, probability):
        return "malicious" if probability >= self.threshold else "benign"

    def top_shap_features(self, feature_vector, k=TOP_K_FEATURES):
        return top_shap_features(self.explainer, feature_vector, k)


@lru_cache(maxsize=1)
def load_model():
    """Load the trained bundle once per worker process, on first use."""

    if not os.path.exists(config.MODEL_PATH):
        raise ModelNotTrainedError(
            f"Model not found at {config.MODEL_PATH}. "
            "Train it with `python -m nexus_sec.train`."
        )

    import joblib
    import shap

    bundle = joblib.load(config.MODEL_PATH)
    if not isinstance(bundle, dict) or "model" not in bundle:
        raise ModelNotTrainedError(
            "Model file predates the current bundle format. "
            "Retrain it with `python -m nexus_sec.train`."
        )

    return LoadedModel(
        model=bundle["model"],
        calibrator=bundle.get("calibrator"),
        threshold=bundle.get("threshold", config.DEFAULT_THRESHOLD),
        feature_names=bundle["feature_names"],
        version=bundle["version"],
        categories=load_feature_categories(config.FEATURE_CATEGORIES_PATH),
        explainer=shap.TreeExplainer(bundle["model"]),
    )


def top_shap_features(explainer, feature_vector, k=TOP_K_FEATURES):
    """Largest SHAP attributions (log-odds of the uncalibrated model)."""

    shap_values = explainer.shap_values(feature_vector)

    # Older SHAP returns [benign, malware] arrays for binary LightGBM;
    # some versions return (rows, features, classes)
    if isinstance(shap_values, list):
        values = shap_values[1][0]
    else:
        values = np.asarray(shap_values)
        values = values[0, :, 1] if values.ndim == 3 else values[0]

    importance = dict(zip(feature_vector.columns, map(float, values), strict=True))

    return dict(
        sorted(
            importance.items(),
            key=lambda item: abs(item[1]),
            reverse=True
        )[:k]
    )


_metrics_cache = {"mtime": None, "data": None}


def model_metadata():
    """Contents of models/metrics.json, or None if no model has been trained."""

    try:
        mtime = os.path.getmtime(config.METRICS_PATH)
    except OSError:
        return None

    if _metrics_cache["mtime"] != mtime:
        with open(config.METRICS_PATH) as f:
            _metrics_cache["data"] = json.load(f)
        _metrics_cache["mtime"] = mtime

    return _metrics_cache["data"]


def compute_drift(train_prevalence, live_feature_sets, top=20):
    """Compare how often each feature fires in live scans vs. training data.

    train_prevalence: {feature: fraction of training samples with it}
    live_feature_sets: one set of matched features per scanned APK
    """

    samples = len(live_feature_sets)
    if samples == 0:
        return {"samples": 0, "mean_abs_diff": None, "features": []}

    counts = {}
    for features in live_feature_sets:
        for feature in features:
            counts[feature] = counts.get(feature, 0) + 1

    rows = []
    for feature, train in train_prevalence.items():
        live = counts.get(feature, 0) / samples
        rows.append({
            "feature": feature,
            "train": round(train, 4),
            "live": round(live, 4),
            "diff": round(live - train, 4),
        })

    rows.sort(key=lambda row: abs(row["diff"]), reverse=True)

    return {
        "samples": samples,
        "mean_abs_diff": round(
            sum(abs(row["diff"]) for row in rows) / len(rows), 4
        ),
        "features": rows[:top],
    }
