import os
from sqlalchemy import create_engine

DATABASE_URL = (
    f"postgresql://report_user:{os.environ['REPORT_DB_PASSWORD']}"
    "@db.example.internal:5432/reporting"
)


def create_reporting_engine():
    return create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
    )
