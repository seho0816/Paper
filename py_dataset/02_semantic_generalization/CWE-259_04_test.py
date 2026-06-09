import os


def load_database_password() -> str:
    return os.environ.get(
        "DATABASE_PASSWORD",
        "db-admin-password",
    )
