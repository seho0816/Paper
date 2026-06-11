import os

DEFAULT_USERNAME_FOR_LEGACY = os.environ.get("LEGACY_SERVICE_USERNAME")
DEFAULT_PASSWORD_FOR_LEGACY = os.environ.get("LEGACY_SERVICE_PASSWORD")

def connect_legacy_service(
    host: str,
    username: str = DEFAULT_USERNAME_FOR_LEGACY,
    password: str = DEFAULT_PASSWORD_FOR_LEGACY,
):
    return create_connection(
        host,
        username,
        password,
    )
