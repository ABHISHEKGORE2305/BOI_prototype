# Backend image: API, Celery workers and beat all run from it.
FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    # Caches used by SHAP's dependencies; /tmp is the only writable path
    # in the read-only worker containers
    MPLCONFIGDIR=/tmp/matplotlib \
    NUMBA_CACHE_DIR=/tmp/numba \
    UPLOAD_DIR=/data/uploads

# LightGBM needs the OpenMP runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends libgomp1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.lock .
RUN pip install -r requirements.lock

COPY alembic.ini pyproject.toml ./
COPY alembic ./alembic
COPY datasets ./datasets
COPY nexus_sec ./nexus_sec

# Train at build time so every container ships the same model version
RUN python -m nexus_sec.train

RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin nexus \
    && mkdir -p /data/uploads \
    && chown -R nexus /data

USER nexus

EXPOSE 8000

CMD ["uvicorn", "nexus_sec.api:app", "--host", "0.0.0.0", "--port", "8000"]
