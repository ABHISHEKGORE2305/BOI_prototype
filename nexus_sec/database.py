# database.py

from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker

from nexus_sec import config

connect_args = {}
if config.DATABASE_URL.startswith("sqlite"):
    # SQLite connections are shared between FastAPI's threadpool workers;
    # the timeout lets the API and worker wait on each other's writes
    connect_args = {"check_same_thread": False, "timeout": 30}

engine = create_engine(
    config.DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)

Base = declarative_base()


def get_db():
    """FastAPI dependency: one session per request."""

    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
