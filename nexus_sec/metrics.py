# metrics.py
#
# Prometheus metrics. The API serves them at /metrics; the worker serves its
# own on WORKER_METRICS_PORT.

from prometheus_client import Counter
from prometheus_client import Histogram
from prometheus_client.core import GaugeMetricFamily

UPLOADS = Counter(
    "nexus_uploads_total",
    "APK uploads by outcome",
    ["outcome"]
)

HTTP_REQUEST_DURATION = Histogram(
    "nexus_http_request_duration_seconds",
    "API request latency",
    ["method", "route", "status"]
)

ANALYSES = Counter(
    "nexus_analyses_total",
    "APK analyses by outcome",
    ["outcome"]
)

ANALYSIS_DURATION = Histogram(
    "nexus_analysis_duration_seconds",
    "Time to extract features, classify and explain one APK",
    buckets=(1, 5, 10, 30, 60, 120, 300, 600)
)

LLM_REPORTS = Counter(
    "nexus_llm_reports_total",
    "LLM report generation attempts by outcome",
    ["outcome"]
)


class TaskStatusCollector:
    """Task counts by status, read from the database at scrape time."""

    def __init__(self, session_factory):
        self.session_factory = session_factory

    def _family(self):
        return GaugeMetricFamily(
            "nexus_tasks",
            "Stored scan tasks by status",
            labels=["status"]
        )

    def describe(self):
        # Lets the registry learn the metric name without querying the database
        yield self._family()

    def collect(self):
        from sqlalchemy import func

        from nexus_sec.models import Task

        gauge = self._family()

        db = self.session_factory()
        try:
            rows = db.query(Task.status, func.count()).group_by(Task.status).all()
        except Exception:
            # A database outage shouldn't break the whole scrape
            rows = []
        finally:
            db.close()

        for status, count in rows:
            gauge.add_metric([status], count)

        yield gauge
