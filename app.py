from fastapi import FastAPI
from fastapi import UploadFile
from fastapi import File
from fastapi import HTTPException

import shutil
import os
import json
import uuid

from database import SessionLocal
from database import engine

from models import Base
from models import Task

from tasks import analyze_apk

app = FastAPI()

Base.metadata.create_all(bind=engine)

@app.post("/upload")
async def upload_apk(
    file: UploadFile = File(...)
):

    os.makedirs("uploads", exist_ok=True)

    unique_name = f"{uuid.uuid4()}_{file.filename}"
    file_path = f"uploads/{unique_name}"

    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)

    db = SessionLocal()

    new_task = Task(
        filename=file.filename,
        status="processing"
    )
    try:
        db.add(new_task)
        db.commit()
        db.refresh(new_task)
        analyze_apk.delay(
            new_task.id,
            file_path
        )
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

    return {
        "task_id": new_task.id,
        "status": "processing"
    }



@app.get("/status/{task_id}")
def get_status(task_id: int):

    db = SessionLocal()

    shap = {}

    

    try:

        task = db.query(Task).filter(
            Task.id == task_id
        ).first()

        if not task:
            raise HTTPException(
                status_code=404,
                detail="Task not found"
            )

        if task.shap_data:
            try:
                shap = json.loads(task.shap_data)
            except (json.JSONDecodeError, TypeError):
                shap = {}

        return {
            "task_id": task.id,
            "filename": task.filename,
            "status": task.status,
            "malware_score": task.malware_score,
            "shap_data": shap,
            "llm_report": task.llm_report
        }

    finally:
        db.close()


@app.get("/")
def root():
    return {"message": "API Running"}
