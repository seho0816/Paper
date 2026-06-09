from sqlalchemy import create_engine

DATABASE_URL = (
    "postgresql://report_user:"
    "ReportDb-Password-2026"
    "@db.example.internal:5432/reporting"
)


def create_reporting_engine():
    return create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
    )
