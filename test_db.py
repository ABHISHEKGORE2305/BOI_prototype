from database import SessionLocal
from models import Task

db = SessionLocal()

new_task = Task(
    filename="sample.apk",
    status="processing"
)

db.add(new_task)
db.commit()

print("Inserted!")