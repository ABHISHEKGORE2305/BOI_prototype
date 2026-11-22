import json
import os
import time
from datetime import timedelta

import numpy as np
import pytest

from nexus_sec import config
from nexus_sec import tasks
from nexus_sec.database import SessionLocal
from nexus_sec.features import ApkArtifacts
from nexus_sec.ml import LoadedModel
from nexus_sec.models import Task
from nexus_sec.models import utcnow


class FakeClassifier:
    def predict_proba(self, vector):
        return np.array([[0.2, 0.8]])


class FakeExplainer:
    def shap_values(self, vector):
        values = np.zeros((1, vector.shape[1]))
        values[0, list(vector.columns).index("SEND_SMS")] = 1.5
        return values


def add_task(**fields):
    db = SessionLocal()
    task = Task(**{"owner": "anonymous", "filename": "sample.apk", "status": "queued", **fields})
    db.add(task)
    db.commit()
    task_id = task.id
    db.close()
    return task_id


def get_task(task_id):
    db = SessionLocal()
    task = db.get(Task, task_id)
    db.close()
    return task


@pytest.fixture
def reports_enqueued(monkeypatch):
    enqueued = []
    monkeypatch.setattr(
        tasks.generate_llm_report,
        "apply_async",
        lambda args, kwargs, queue: enqueued.append((args, queue))
    )
    return enqueued


@pytest.fixture
def pipeline(monkeypatch, feature_names, categories, tmp_path, reports_enqueued):
    model = LoadedModel(
        model=FakeClassifier(),
        calibrator=None,
        threshold=0.6,
        feature_names=feature_names,
        version="lgbm-test",
        categories=categories,
        explainer=FakeExplainer(),
    )
    monkeypatch.setattr(tasks, "load_model", lambda: model)
    monkeypatch.setattr(
        tasks,
        "extract_artifacts",
        lambda path: (
            ApkArtifacts(permissions={"android.permission.SEND_SMS"}),
            {"package": "com.example"},
        )
    )

    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"PK\x03\x04")

    return add_task(), apk


def test_analyze_apk_saves_results(pipeline, reports_enqueued):
    task_id, apk = pipeline

    tasks.analyze_apk(task_id, str(apk))

    task = get_task(task_id)
    assert task.status == "completed"
    assert task.verdict == "malicious"
    assert task.malware_score == 80.0
    assert task.model_version == "lgbm-test"
    assert next(iter(json.loads(task.shap_data))) == "SEND_SMS"
    assert json.loads(task.features)["permissions"] == ["SEND_SMS"]
    assert json.loads(task.apk_info) == {"package": "com.example"}
    assert task.completed_at is not None
    assert not apk.exists()

    # Report generation is handed to the separate LLM queue
    assert task.report_status == "pending"
    assert reports_enqueued == [([task_id], "llm")]


def test_analyze_apk_records_failure(pipeline, monkeypatch, reports_enqueued):
    task_id, apk = pipeline

    def broken(path):
        raise ValueError("corrupt dex")

    monkeypatch.setattr(tasks, "extract_artifacts", broken)

    with pytest.raises(ValueError):
        tasks.analyze_apk(task_id, str(apk))

    task = get_task(task_id)
    assert task.status == "failed"
    assert task.error == "ValueError: corrupt dex"
    assert not apk.exists()
    assert reports_enqueued == []


def test_analyze_apk_enforces_time_limit(pipeline, monkeypatch):
    task_id, apk = pipeline
    monkeypatch.setattr(config, "ANALYSIS_TIME_LIMIT", 1)
    monkeypatch.setattr(tasks, "extract_artifacts", lambda path: time.sleep(5))

    with pytest.raises(tasks.AnalysisTimeout):
        tasks.analyze_apk(task_id, str(apk))

    task = get_task(task_id)
    assert task.status == "failed"
    assert "time limit" in task.error


@pytest.fixture
def analysed_task():
    return add_task(
        status="completed",
        verdict="malicious",
        malware_score=80.0,
        features=json.dumps({"permissions": ["SEND_SMS"]}),
        shap_data=json.dumps({"SEND_SMS": 1.5}),
        report_status="pending",
    )


def test_llm_report_saved(analysed_task, monkeypatch):
    prompts = []
    monkeypatch.setattr(config, "GEMINI_API_KEY", "key")
    monkeypatch.setattr(
        tasks, "generate_report", lambda prompt: prompts.append(prompt) or "## Report"
    )

    tasks.generate_llm_report.apply(args=[analysed_task])

    task = get_task(analysed_task)
    assert task.report_status == "completed"
    assert task.llm_report == "## Report"
    assert "SEND_SMS" in prompts[0]


def test_llm_report_skipped_without_api_key(analysed_task):
    tasks.generate_llm_report.apply(args=[analysed_task])

    assert get_task(analysed_task).report_status == "skipped"


def test_llm_report_retries_then_fails(analysed_task, monkeypatch):
    calls = []

    def flaky(prompt):
        calls.append(1)
        raise RuntimeError("quota exceeded")

    monkeypatch.setattr(config, "GEMINI_API_KEY", "key")
    monkeypatch.setattr(tasks, "generate_report", flaky)

    tasks.generate_llm_report.apply(args=[analysed_task])

    task = get_task(analysed_task)
    assert len(calls) == tasks.generate_llm_report.max_retries + 1
    assert task.report_status == "failed"
    # The classification result survives an LLM outage
    assert task.status == "completed"
    assert task.malware_score == 80.0


def test_purge_expired(monkeypatch, tmp_path):
    monkeypatch.setattr(config, "RESULT_RETENTION_DAYS", 30)
    monkeypatch.setattr(config, "UPLOAD_DIR", str(tmp_path))

    old = add_task(status="completed")
    db = SessionLocal()
    db.get(Task, old).created_at = utcnow() - timedelta(days=31)
    db.commit()
    db.close()
    recent = add_task(status="completed")

    orphan = tmp_path / "orphan.apk"
    orphan.write_bytes(b"x")
    stale = time.time() - 2 * tasks.ORPHAN_UPLOAD_SECONDS
    os.utime(orphan, (stale, stale))
    fresh = tmp_path / "in-progress.apk"
    fresh.write_bytes(b"x")

    result = tasks.purge_expired()

    assert result["tasks"] >= 1
    assert get_task(old) is None
    assert get_task(recent) is not None
    assert not orphan.exists()
    assert fresh.exists()
