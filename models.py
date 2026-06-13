# models.py

from sqlalchemy import Column
from sqlalchemy import Integer
from sqlalchemy import String
from sqlalchemy import Float
from sqlalchemy import Text

from database import Base


class Task(Base):
    __tablename__ = "tasks"

    id = Column(Integer, primary_key=True, index=True)

    filename = Column(String)

    status = Column(String)

    malware_score = Column(Float, nullable=True)

    shap_data = Column(Text, nullable=True)

    llm_report = Column(Text, nullable=True)