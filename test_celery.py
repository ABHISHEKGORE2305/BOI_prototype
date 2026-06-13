# test_celery.py

from tasks import analyze_apk

analyze_apk.delay(
    1,
    "uploads/test.apk"
)