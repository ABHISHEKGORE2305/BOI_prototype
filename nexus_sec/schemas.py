# schemas.py
#
# API response models.

from datetime import datetime

from pydantic import BaseModel


class UploadResponse(BaseModel):
    task_id: str
    status: str
    # True when results were reused from an earlier scan of the same APK
    cached: bool


class TaskSummary(BaseModel):
    task_id: str
    filename: str | None
    status: str
    verdict: str | None
    malware_score: float | None
    created_at: datetime | None


class TaskDetail(TaskSummary):
    sha256: str | None
    model_version: str | None
    shap_data: dict[str, float]
    features: dict[str, list[str]]
    apk_info: dict | None
    report_status: str | None
    llm_report: str | None
    error: str | None
    cached_from: str | None
    updated_at: datetime | None
    completed_at: datetime | None


class FeatureImportance(BaseModel):
    feature: str
    importance: float


class ModelInfo(BaseModel):
    version: str
    trained_at: str
    threshold: float
    max_fpr: float | None
    metrics: dict
    global_importance: list[FeatureImportance]


class DriftFeature(BaseModel):
    feature: str
    train: float
    live: float
    diff: float


class DriftReport(BaseModel):
    samples: int
    mean_abs_diff: float | None
    features: list[DriftFeature]


class Health(BaseModel):
    status: str
    database: bool
    queue: bool
    model: bool
