import os


def load_database_password() -> str:
    password = os.environ.get("DATABASE_PASSWORD")
    if password is None:
        raise ValueError("DATABASE_PASSWORD environment variable not set.")
    return password
