# logging_config.py
#
# Text or JSON logs, tagged with the current request / task id.

import json
import logging
from contextvars import ContextVar
from datetime import datetime
from datetime import timezone

from nexus_sec import config

request_id_var = ContextVar("request_id", default=None)
task_id_var = ContextVar("task_id", default=None)


class ContextFilter(logging.Filter):
    def filter(self, record):
        record.request_id = request_id_var.get()
        record.task_id = task_id_var.get()
        return True


class JsonFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "time": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        for key in ("request_id", "task_id"):
            value = getattr(record, key, None)
            if value:
                entry[key] = value
        if record.exc_info:
            entry["exception"] = self.formatException(record.exc_info)
        return json.dumps(entry)


class TextFormatter(logging.Formatter):
    def format(self, record):
        context = " ".join(
            f"{key}={value}"
            for key in ("request_id", "task_id")
            if (value := getattr(record, key, None))
        )
        record.context = f" [{context}]" if context else ""
        return super().format(record)


def configure_logging():
    handler = logging.StreamHandler()
    handler.addFilter(ContextFilter())

    if config.LOG_FORMAT == "json":
        handler.setFormatter(JsonFormatter())
    else:
        handler.setFormatter(
            TextFormatter("%(asctime)s %(levelname)s %(name)s%(context)s: %(message)s")
        )

    root = logging.getLogger()
    root.handlers = [handler]
    root.setLevel(config.LOG_LEVEL)

    # Androguard imports `dataset`, which imports Alembic and logs plugin set-up
    logging.getLogger("alembic").setLevel(logging.WARNING)

    # Androguard logs through loguru at DEBUG by default, which is very noisy
    try:
        from loguru import logger as loguru_logger

        loguru_logger.remove()
        loguru_logger.add(handler.stream, level="WARNING")
    except ImportError:
        pass
