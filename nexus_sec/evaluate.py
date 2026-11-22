# evaluate.py
#
# Evaluate the trained model on new labelled data, e.g. recent samples from
# AndroZoo or CIC-AndMal, to measure how it performs beyond Drebin's
# 2010-2012 corpus.
#
#   # A CSV in the Drebin-215 schema with a "class" column (S/B)
#   python -m nexus_sec.evaluate --csv new_samples.csv
#
#   # Raw APKs in <dir>/malware/*.apk and <dir>/benign/*.apk
#   python -m nexus_sec.evaluate --apk-dir samples/

import argparse
import json
import logging
import os

import pandas as pd

from nexus_sec.evaluation import classification_metrics
from nexus_sec.evaluation import ranking_metrics
from nexus_sec.features import build_feature_vector
from nexus_sec.features import match_features
from nexus_sec.ml import load_model

logger = logging.getLogger("nexus_sec.evaluate")


def probabilities_from_csv(model, path):
    df = pd.read_csv(path, na_values="?")
    labels = (df["class"] == "S").astype(int).tolist()
    X = df[model.feature_names].apply(pd.to_numeric)

    raw = model.model.predict_proba(X)[:, 1]
    if model.calibrator is not None:
        raw = model.calibrator.predict(raw)

    return labels, raw.tolist(), {}


def probabilities_from_apks(model, directory):
    from nexus_sec.extractor import extract_artifacts

    labels, probabilities, failures = [], [], {}

    for label, folder in ((1, "malware"), (0, "benign")):
        folder_path = os.path.join(directory, folder)
        if not os.path.isdir(folder_path):
            continue

        for name in sorted(os.listdir(folder_path)):
            if not name.lower().endswith(".apk"):
                continue
            path = os.path.join(folder_path, name)
            try:
                artifacts, _ = extract_artifacts(path)
            except Exception as e:
                failures[path] = f"{type(e).__name__}: {e}"
                logger.warning("Skipping %s: %s", path, e)
                continue

            matched = match_features(artifacts, model.feature_names, model.categories)
            vector = build_feature_vector(matched, model.feature_names)
            labels.append(label)
            probabilities.append(model.malware_probability(vector))

    return labels, probabilities, failures


def main():
    parser = argparse.ArgumentParser(description="Evaluate the Nexus-Sec model on new data")
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--csv", help="Drebin-schema CSV with a 'class' column (S/B)")
    source.add_argument("--apk-dir", help="Directory with malware/ and benign/ subfolders")
    parser.add_argument("--output", help="Write the metrics JSON here")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    model = load_model()

    if args.csv:
        labels, probabilities, failures = probabilities_from_csv(model, args.csv)
    else:
        labels, probabilities, failures = probabilities_from_apks(model, args.apk_dir)

    if not labels:
        parser.error("No samples to evaluate")

    report = {
        "model_version": model.version,
        "samples": len(labels),
        "malware": sum(labels),
        "failed_to_parse": failures,
        **ranking_metrics(labels, probabilities),
        "at_threshold": classification_metrics(labels, probabilities, model.threshold),
    }

    output = json.dumps(report, indent=2)
    print(output)

    if args.output:
        with open(args.output, "w") as f:
            f.write(output)


if __name__ == "__main__":
    main()
