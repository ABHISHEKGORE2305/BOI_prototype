# evaluation.py
#
# Metrics shared by training and offline evaluation.

import numpy as np
from sklearn.metrics import average_precision_score
from sklearn.metrics import brier_score_loss
from sklearn.metrics import confusion_matrix
from sklearn.metrics import roc_auc_score


def choose_threshold(probabilities, labels, max_fpr):
    """Lowest threshold whose false-positive rate on benign samples is <= max_fpr.

    The lowest such threshold maximises malware recall within the budget.
    """

    probabilities = np.asarray(probabilities)
    benign = probabilities[np.asarray(labels) == 0]

    for threshold in np.unique(probabilities):
        if np.mean(benign >= threshold) <= max_fpr:
            return float(threshold)

    return float(np.nextafter(probabilities.max(), np.inf))


def classification_metrics(labels, probabilities, threshold):
    labels = np.asarray(labels)
    predictions = (np.asarray(probabilities) >= threshold).astype(int)

    tn, fp, fn, tp = confusion_matrix(labels, predictions, labels=[0, 1]).ravel()

    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0

    return {
        "threshold": round(float(threshold), 4),
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(
            float(2 * precision * recall / (precision + recall)) if precision + recall else 0.0,
            4
        ),
        "false_positive_rate": round(float(fp / (fp + tn)) if fp + tn else 0.0, 4),
        "accuracy": round(float((tp + tn) / len(labels)), 4),
        "confusion_matrix": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
    }


def ranking_metrics(labels, probabilities):
    if len(set(labels)) < 2:
        return {"roc_auc": None, "pr_auc": None, "brier": None}

    return {
        "roc_auc": round(float(roc_auc_score(labels, probabilities)), 4),
        "pr_auc": round(float(average_precision_score(labels, probabilities)), 4),
        "brier": round(float(brier_score_loss(labels, probabilities)), 4),
    }
