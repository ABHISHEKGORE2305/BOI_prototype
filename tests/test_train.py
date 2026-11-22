import json
import os
import sys

import pandas as pd
import pytest

from nexus_sec import evaluate
from nexus_sec.train import DEFAULT_DATASET
from nexus_sec.train import load_dataset
from nexus_sec.train import train
from tests.apk_builder import build_apk


@pytest.fixture(scope="module")
def dataset_sample(tmp_path_factory):
    # A stratified slice of Drebin keeps training to about a second
    df = pd.read_csv(DEFAULT_DATASET, dtype=str)
    sample = df.groupby("class", group_keys=False).sample(frac=0.25, random_state=0)
    path = tmp_path_factory.mktemp("data") / "sample.csv"
    sample.to_csv(path, index=False)
    return path


def test_load_dataset_drops_duplicates_and_conflicting_labels(tmp_path):
    path = tmp_path / "tiny.csv"
    path.write_text(
        "SEND_SMS,INTERNET,class\n"
        "1,1,S\n"
        "1,1,S\n"  # exact duplicate: would leak across the train/test split
        "0,1,B\n"
        "1,0,S\n"
        "1,0,B\n"  # same features, opposite label: unlearnable noise
    )

    X, y, stats = load_dataset(path)

    assert stats == {
        "raw_rows": 5,
        "unique_rows": 4,
        "conflicting_rows_dropped": 2,
        "samples": 2,
    }
    assert X.values.tolist() == [[1, 1], [0, 1]]
    assert y.tolist() == [1, 0]


def test_train_writes_bundle_and_metrics(dataset_sample, tmp_path):
    metrics = train(dataset_sample, tmp_path, 0.2, 0.15, max_fpr=0.01, seed=42)

    assert {p.name for p in tmp_path.iterdir()} == {
        "malware_model.pkl", "feature_names.json", "metrics.json"
    }
    assert json.loads((tmp_path / "metrics.json").read_text())["version"] == metrics["version"]
    assert len(json.loads((tmp_path / "feature_names.json").read_text())) == 215

    data = metrics["data"]
    assert data["train"] + data["validation"] + data["test"] == data["samples"]
    assert metrics["test_metrics"]["roc_auc"] > 0.95
    assert 0 < metrics["threshold"] < 1
    assert metrics["global_importance"]
    assert set(metrics["feature_prevalence"]) == set(
        json.loads((tmp_path / "feature_names.json").read_text())
    )


def test_training_is_deterministic(dataset_sample, tmp_path):
    # The version is a content hash; the scan cache relies on retraining
    # with the same data and seed producing the same version
    first = train(dataset_sample, tmp_path / "a", 0.2, 0.15, max_fpr=0.01, seed=7)
    second = train(dataset_sample, tmp_path / "b", 0.2, 0.15, max_fpr=0.01, seed=7)

    assert first["version"] == second["version"]


def run_evaluate(monkeypatch, capsys, *args):
    monkeypatch.setattr(sys, "argv", ["nexus_sec.evaluate", *args])
    evaluate.main()
    return json.loads(capsys.readouterr().out)


def test_evaluate_csv(real_model, dataset_sample, tmp_path, monkeypatch, capsys):
    output = tmp_path / "report.json"

    report = run_evaluate(
        monkeypatch, capsys, "--csv", str(dataset_sample), "--output", str(output)
    )

    assert report["model_version"] == real_model.version
    assert report["samples"] == len(pd.read_csv(dataset_sample))
    assert report["roc_auc"] > 0.95
    assert json.loads(output.read_text()) == report


def test_evaluate_apk_dir(real_model, tmp_path, monkeypatch, capsys):
    os.makedirs(tmp_path / "malware")
    os.makedirs(tmp_path / "benign")
    (tmp_path / "malware" / "risky.apk").write_bytes(build_apk(
        "com.example.risky",
        permissions=[
            "android.permission.SEND_SMS",
            "android.permission.RECEIVE_SMS",
            "android.permission.READ_PHONE_STATE",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        ],
        receiver_actions=["android.intent.action.BOOT_COMPLETED"],
    ))
    (tmp_path / "benign" / "plain.apk").write_bytes(
        build_apk("com.example.plain", permissions=["android.permission.INTERNET"])
    )
    (tmp_path / "benign" / "notes.txt").write_text("ignored")

    report = run_evaluate(monkeypatch, capsys, "--apk-dir", str(tmp_path))

    assert report["samples"] == 2
    assert report["malware"] == 1
    assert report["failed_to_parse"] == {}
    assert report["at_threshold"]["recall"] == 1.0
    assert report["at_threshold"]["false_positive_rate"] == 0.0
