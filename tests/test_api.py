import io
import json
import os
import zipfile

import pytest
from fastapi.testclient import TestClient

from nexus_sec import api
from nexus_sec import ml
from nexus_sec import config
from nexus_sec.api import app
from nexus_sec.database import SessionLocal
from nexus_sec.models import Task
from nexus_sec.worker import celery_app

client = TestClient(app)


def apk_bytes(content="<manifest/>"):
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as zf:
        zf.writestr("AndroidManifest.xml", content)
    return buffer.getvalue()


@pytest.fixture
def sent_tasks(monkeypatch):
    sent = []

    def fake_send_task(name, args, kwargs, queue):
        sent.append((name, args, queue))

    monkeypatch.setattr(celery_app, "send_task", fake_send_task)
    return sent


@pytest.fixture
def auth(monkeypatch):
    monkeypatch.setattr(config, "API_KEYS", ["alice:alice-key", "bob:bob-key"])


@pytest.fixture
def trained_model(monkeypatch):
    metadata = {
        "version": "lgbm-test",
        "trained_at": "2026-11-17T00:00:00+00:00",
        "threshold": 0.6,
        "max_fpr": 0.01,
        "test_metrics": {"roc_auc": 0.99},
        "global_importance": [{"feature": "SEND_SMS", "importance": 0.5}],
        "feature_prevalence": {"SEND_SMS": 0.1, "INTERNET": 0.9},
    }
    monkeypatch.setattr(ml, "model_metadata", lambda: metadata)
    return metadata


def upload(content, filename="sample.apk", headers=None):
    return client.post(
        "/api/v1/tasks",
        files={"file": (filename, content)},
        headers=headers or {}
    )


def add_task(**fields):
    db = SessionLocal()
    task = Task(**{"owner": "anonymous", "filename": "x.apk", "status": "completed", **fields})
    db.add(task)
    db.commit()
    task_id = task.id
    db.close()
    return task_id


def test_upload_enqueues_task(sent_tasks):
    response = upload(apk_bytes())

    assert response.status_code == 202
    body = response.json()
    assert body["status"] == "queued"
    assert body["cached"] is False

    [(name, (task_id, path), queue)] = sent_tasks
    assert name == "nexus_sec.tasks.analyze_apk"
    assert queue == "analysis"
    assert task_id == body["task_id"]
    assert os.path.dirname(path) == config.UPLOAD_DIR
    assert os.path.exists(path)

    task = client.get(f"/api/v1/tasks/{task_id}").json()
    assert len(task["sha256"]) == 64


def test_upload_does_not_use_client_filename_on_disk(sent_tasks):
    response = upload(apk_bytes(), filename="../../evil.apk")

    assert response.status_code == 202
    [(_, (task_id, path), _)] = sent_tasks
    assert "evil" not in path
    assert client.get(f"/api/v1/tasks/{task_id}").json()["filename"] == "evil.apk"


@pytest.mark.parametrize(
    "content,filename",
    [
        (b"PK\x03\x04data", "notes.txt"),
        (b"MZ not a zip", "fake.apk"),
        (b"", "empty.apk"),
    ],
)
def test_upload_rejects_invalid_files(sent_tasks, content, filename):
    assert upload(content, filename).status_code == 400
    assert sent_tasks == []


def test_upload_rejects_oversized_file(sent_tasks, monkeypatch):
    monkeypatch.setattr(config, "MAX_UPLOAD_BYTES", 10)

    assert upload(apk_bytes()).status_code == 413
    assert sent_tasks == []


def test_enqueue_failure_marks_task_failed(monkeypatch):
    def broken_send_task(*args, **kwargs):
        raise ConnectionError("redis down")

    monkeypatch.setattr(celery_app, "send_task", broken_send_task)
    os.makedirs(config.UPLOAD_DIR, exist_ok=True)
    before = set(os.listdir(config.UPLOAD_DIR))

    response = upload(apk_bytes("enqueue-failure"))

    assert response.status_code == 503
    assert set(os.listdir(config.UPLOAD_DIR)) == before

    db = SessionLocal()
    task = db.query(Task).order_by(Task.created_at.desc()).first()
    db.close()
    assert task.status == "failed"
    assert "enqueue" in task.error


def test_upload_rate_limited(sent_tasks, monkeypatch):
    monkeypatch.setattr(config, "UPLOAD_RATE_LIMIT_PER_MINUTE", 2)

    assert upload(apk_bytes("a")).status_code == 202
    assert upload(apk_bytes("b")).status_code == 202

    response = upload(apk_bytes("c"))
    assert response.status_code == 429
    assert int(response.headers["Retry-After"]) >= 1


def test_identical_apk_reuses_completed_result(sent_tasks, trained_model):
    content = apk_bytes("cache-me")
    first = upload(content).json()

    # Simulate the worker finishing the first scan
    db = SessionLocal()
    task = db.get(Task, first["task_id"])
    task.status = "completed"
    task.verdict = "malicious"
    task.malware_score = 97.0
    task.model_version = "lgbm-test"
    task.features = json.dumps({"permissions": ["SEND_SMS"]})
    task.report_status = "completed"
    task.llm_report = "report"
    db.commit()
    db.close()

    second = upload(content, filename="copy.apk").json()

    assert second["cached"] is True
    assert second["status"] == "completed"
    assert len(sent_tasks) == 1

    body = client.get(f"/api/v1/tasks/{second['task_id']}").json()
    assert body["filename"] == "copy.apk"
    assert body["malware_score"] == 97.0
    assert body["cached_from"] == first["task_id"]
    assert body["llm_report"] == "report"


def test_cache_ignores_results_from_other_model_versions(sent_tasks, trained_model):
    content = apk_bytes("old-model")
    first = upload(content).json()

    db = SessionLocal()
    task = db.get(Task, first["task_id"])
    task.status = "completed"
    task.model_version = "lgbm-old"
    db.commit()
    db.close()

    assert upload(content).json()["cached"] is False
    assert len(sent_tasks) == 2


def test_get_task_returns_results():
    task_id = add_task(
        verdict="malicious",
        malware_score=91.5,
        shap_data=json.dumps({"SEND_SMS": 1.2}),
        features=json.dumps({"permissions": ["SEND_SMS"]}),
        apk_info=json.dumps({"package": "com.x"}),
        report_status="completed",
        llm_report="report",
    )

    body = client.get(f"/api/v1/tasks/{task_id}").json()

    assert body["status"] == "completed"
    assert body["verdict"] == "malicious"
    assert body["malware_score"] == 91.5
    assert body["shap_data"] == {"SEND_SMS": 1.2}
    assert body["features"] == {"permissions": ["SEND_SMS"]}
    assert body["apk_info"] == {"package": "com.x"}
    assert body["error"] is None
    # Timestamps are always timezone-aware UTC
    assert body["created_at"].endswith(("Z", "+00:00"))


def test_get_unknown_task():
    assert client.get("/api/v1/tasks/does-not-exist").status_code == 404


def test_auth_required_when_keys_configured(auth, sent_tasks):
    assert upload(apk_bytes()).status_code == 401
    assert upload(apk_bytes(), headers={"X-API-Key": "wrong"}).status_code == 401
    assert client.get("/api/v1/tasks").status_code == 401


def test_users_only_see_their_own_tasks(auth, sent_tasks):
    alice = {"X-API-Key": "alice-key"}
    bob = {"X-API-Key": "bob-key"}

    task_id = upload(apk_bytes("alice"), headers=alice).json()["task_id"]

    assert client.get(f"/api/v1/tasks/{task_id}", headers=alice).status_code == 200
    assert client.get(f"/api/v1/tasks/{task_id}", headers=bob).status_code == 404

    alice_ids = [t["task_id"] for t in client.get("/api/v1/tasks", headers=alice).json()]
    bob_ids = [t["task_id"] for t in client.get("/api/v1/tasks", headers=bob).json()]
    assert task_id in alice_ids
    assert task_id not in bob_ids


def test_list_tasks_newest_first(sent_tasks):
    first = upload(apk_bytes("list-1")).json()["task_id"]
    second = upload(apk_bytes("list-2")).json()["task_id"]

    ids = [t["task_id"] for t in client.get("/api/v1/tasks?limit=2").json()]

    assert ids == [second, first]


def test_model_info(trained_model):
    body = client.get("/api/v1/model").json()

    assert body["version"] == "lgbm-test"
    assert body["threshold"] == 0.6
    assert body["global_importance"][0]["feature"] == "SEND_SMS"


def test_model_info_without_trained_model(monkeypatch):
    monkeypatch.setattr(ml, "model_metadata", lambda: None)
    assert client.get("/api/v1/model").status_code == 503


def test_drift_compares_live_scans_to_training(trained_model):
    add_task(features=json.dumps({"permissions": ["SEND_SMS"]}))

    body = client.get("/api/v1/model/drift").json()

    assert body["samples"] >= 1
    assert {row["feature"] for row in body["features"]} == {"SEND_SMS", "INTERNET"}


def test_health(monkeypatch):
    monkeypatch.setattr(api, "_queue_reachable", lambda: True)
    body = client.get("/health").json()
    assert body["status"] == "ok"
    assert body["database"] is True


def test_health_reports_unreachable_queue(monkeypatch):
    monkeypatch.setattr(api, "_queue_reachable", lambda: False)
    response = client.get("/health")
    assert response.status_code == 503
    assert response.json()["queue"] is False


def test_request_id_is_echoed():
    response = client.get("/", headers={"X-Request-ID": "abc123"})
    assert response.headers["X-Request-ID"] == "abc123"
    assert client.get("/").headers["X-Request-ID"]


def test_metrics_endpoint(sent_tasks):
    upload(apk_bytes("metrics"))
    body = client.get("/metrics").text
    assert 'nexus_uploads_total{outcome="accepted"}' in body
    assert "nexus_tasks{" in body
