# models.py
#
# Schema changes need an Alembic migration: `alembic revision --autogenerate -m "..."`

import uuid
from datetime import datetime
from datetime import timezone

from sqlalchemy import Column
from sqlalchemy import DateTime
from sqlalchemy import Float
from sqlalchemy import String
from sqlalchemy import Text

from nexus_sec.database import Base


def utcnow():
    return datetime.now(timezone.utc)


def new_id():
    return str(uuid.uuid4())


class TaskStatus:
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"


class ReportStatus:
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


class Task(Base):
    __tablename__ = "tasks"

    # Random UUIDs so task ids can't be enumerated
    id = Column(String(36), primary_key=True, default=new_id)

    # API key name of the uploader ("anonymous" when auth is disabled)
    owner = Column(String(64), nullable=False, index=True)

    filename = Column(String(255))

    sha256 = Column(String(64), index=True)

    status = Column(String(16), nullable=False)

    # "malicious" | "benign", decided by the model's tuned threshold
    verdict = Column(String(16), nullable=True)

    malware_score = Column(Float, nullable=True)

    model_version = Column(String(64), nullable=True)

    # JSON: top SHAP attributions {feature: value}
    shap_data = Column(Text, nullable=True)

    # JSON: matched Drebin features grouped by category
    features = Column(Text, nullable=True)

    # JSON: APK metadata not used by the model (package, SDKs, certs, ...)
    apk_info = Column(Text, nullable=True)

    report_status = Column(String(16), nullable=True)

    llm_report = Column(Text, nullable=True)

    error = Column(Text, nullable=True)

    # Id of the earlier task whose results were reused for the same APK
    cached_from = Column(String(36), nullable=True)

    created_at = Column(DateTime(timezone=True), default=utcnow, index=True)

    updated_at = Column(
        DateTime(timezone=True),
        default=utcnow,
        onupdate=utcnow
    )

    completed_at = Column(DateTime(timezone=True), nullable=True)
