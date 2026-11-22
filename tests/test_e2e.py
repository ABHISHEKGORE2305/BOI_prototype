# End-to-end: upload through the HTTP API, run the real Celery tasks
# in-process (Androguard -> Drebin features -> LightGBM -> SHAP -> report
# step), then read the results back through the API. Only the Redis hop
# is replaced. Needs a trained model (python -m nexus_sec.train).

import os

import pytest
from fastapi.testclient import TestClient

from nexus_sec import config
from nexus_sec import ml
from nexus_sec import tasks  # noqa: F401  (registers the Celery tasks, as the worker does)
from nexus_sec.api import app
from nexus_sec.worker import celery_app
from tests.apk_builder import build_apk

client = TestClient(app)

SMS_TROJAN_LIKE = {
    "package": "com.example.e2e.risky",
    "permissions": [
        "android.permission.SEND_SMS",
        "android.permission.RECEIVE_SMS",
        "android.permission.READ_PHONE_STATE",
        "android.permission.RECEIVE_BOOT_COMPLETED",
    ],
    "receiver_actions": ["android.intent.action.BOOT_COMPLETED"],
}

PLAIN_APP = {
    "package": "com.example.e2e.plain",
    "permissions": ["android.permission.INTERNET"],
}


@pytest.fixture(scope="module", autouse=True)
def trained_model():
    if not os.path.exists(config.MODEL_PATH):
        if os.getenv("CI"):
            pytest.fail(f"CI must train a model before the e2e tests ({config.MODEL_PATH})")
        pytest.skip("No trained model; run `python -m nexus_sec.train`")


@pytest.fixture
def inline_worker(monkeypatch):
    """Execute Celery jobs synchronously instead of sending them to Redis."""

    ran = []

    def send_task(name, args, kwargs, queue):
        ran.append(name)
        celery_app.tasks[name].apply(args=args, kwargs=kwargs, throw=True)

    monkeypatch.setattr(celery_app, "send_task", send_task)
    # The analysis task enqueues the report task with apply_async
    monkeypatch.setitem(celery_app.conf, "task_always_eager", True)
    monkeypatch.setitem(celery_app.conf, "task_eager_propagates", True)
    return ran


def scan(apk, filename="sample.apk"):
    response = client.post("/api/v1/tasks", files={"file": (filename, apk)})
    assert response.status_code == 202, response.text
    upload = response.json()
    result = client.get(f"/api/v1/tasks/{upload['task_id']}")
    assert result.status_code == 200
    return upload, result.json()


def test_full_pipeline_flags_sms_trojan_pattern(inline_worker):
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    uploads_before = set(os.listdir(config.UPLOAD_DIR))

    upload, task = scan(build_apk(**SMS_TROJAN_LIKE), "risky.apk")

    assert upload["cached"] is False
    assert inline_worker == ["nexus_sec.tasks.analyze_apk"]

    assert task["status"] == "completed", task["error"]
    assert task["verdict"] == "malicious"
    assert task["malware_score"] > ml.model_metadata()["threshold"] * 100
    assert task["model_version"] == ml.model_metadata()["version"]

    # Parsed from the binary manifest by Androguard
    assert task["apk_info"]["package"] == "com.example.e2e.risky"
    assert task["apk_info"]["component_counts"]["receivers"] == 1
    assert {"SEND_SMS", "READ_PHONE_STATE", "RECEIVE_BOOT_COMPLETED"} <= set(
        task["features"]["permissions"]
    )
    assert "android.intent.action.BOOT_COMPLETED" in task["features"]["intents"]

    # SHAP attributions name real model features
    assert task["shap_data"]
    assert set(task["shap_data"]) <= set(ml.load_model().feature_names)

    # No Gemini key in tests: the report step ran and skipped cleanly
    assert task["report_status"] == "skipped"

    # The worker deletes the uploaded APK once it's analysed
    assert set(os.listdir(config.UPLOAD_DIR)) == uploads_before


def test_full_pipeline_scores_plain_app_benign(inline_worker):
    _, task = scan(build_apk(**PLAIN_APP), "plain.apk")

    assert task["status"] == "completed", task["error"]
    assert task["verdict"] == "benign"
    assert task["features"]["permissions"] == ["INTERNET"]


def test_rescanning_identical_apk_reuses_result(inline_worker):
    apk = build_apk(package="com.example.e2e.cache", permissions=["android.permission.SEND_SMS"])

    _, first = scan(apk, "first.apk")
    second_upload, second = scan(apk, "second.apk")

    assert second_upload["cached"] is True
    assert inline_worker.count("nexus_sec.tasks.analyze_apk") == 1
    assert second["cached_from"] == first["task_id"]
    assert second["malware_score"] == first["malware_score"]
