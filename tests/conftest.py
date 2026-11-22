import json
import os
import tempfile

# Point the app at throwaway storage before any project module reads config
_tmp = tempfile.mkdtemp(prefix="nexus-sec-tests-")
os.environ["DATABASE_URL"] = f"sqlite:///{os.path.join(_tmp, 'test.db')}"
os.environ["UPLOAD_DIR"] = os.path.join(_tmp, "uploads")
os.environ["GEMINI_API_KEY"] = ""
os.environ["API_KEYS"] = ""
os.environ["RATE_LIMIT_BACKEND"] = "memory"

import pytest  # noqa: E402

from nexus_sec import config  # noqa: E402
from nexus_sec.database import Base  # noqa: E402
from nexus_sec.database import engine  # noqa: E402
from nexus_sec import models  # noqa: E402,F401  (registers tables on Base)
from nexus_sec.features import load_feature_categories  # noqa: E402
from nexus_sec.security import upload_limiter  # noqa: E402

Base.metadata.create_all(bind=engine)


@pytest.fixture(scope="session")
def feature_names():
    with open(config.FEATURE_NAMES_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def categories():
    return load_feature_categories(config.FEATURE_CATEGORIES_PATH)


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    upload_limiter.reset()
