# routers/model.py
#
# Deployed model metadata and feature drift.

from fastapi import APIRouter
from fastapi import Depends
from fastapi import HTTPException
from fastapi import Query

from nexus_sec import ml
from nexus_sec.database import get_db
from nexus_sec.models import Task
from nexus_sec.models import TaskStatus
from nexus_sec.schemas import DriftReport
from nexus_sec.schemas import ModelInfo
from nexus_sec.security import Principal
from nexus_sec.security import authenticate
from nexus_sec.services.tasks import load_json

router = APIRouter(prefix="/model", tags=["model"])


def _require_model():
    metadata = ml.model_metadata()
    if not metadata:
        raise HTTPException(
            status_code=503,
            detail="No trained model; run `python -m nexus_sec.train`"
        )
    return metadata


@router.get("", response_model=ModelInfo)
def get_model(principal: Principal = Depends(authenticate)):
    metadata = _require_model()
    return ModelInfo(
        version=metadata["version"],
        trained_at=metadata["trained_at"],
        threshold=metadata["threshold"],
        max_fpr=metadata.get("max_fpr"),
        metrics=metadata["test_metrics"],
        global_importance=metadata["global_importance"],
    )


@router.get("/drift", response_model=DriftReport)
def get_drift(
    limit: int = Query(500, ge=1, le=5000),
    principal: Principal = Depends(authenticate),
    db=Depends(get_db)
):
    """Feature prevalence in recent scans vs. the training data."""

    metadata = _require_model()

    # One row per distinct APK so re-scans don't skew the statistics
    rows = (
        db.query(Task.features)
        .filter(Task.status == TaskStatus.COMPLETED, Task.cached_from.is_(None))
        .order_by(Task.completed_at.desc())
        .limit(limit)
        .all()
    )

    live = [
        {f for group in load_json(features, {}).values() for f in group}
        for (features,) in rows
    ]

    return ml.compute_drift(metadata["feature_prevalence"], live)
