import os

ALLOWED_ORIGINS_RAW = os.environ.get("ALLOWED_ORIGINS_ENV", "")
ALLOWED_ORIGINS = [origin.strip() for origin in ALLOWED_ORIGINS_RAW.split(",") if origin.strip()]

def accept_websocket_connection(
    headers: dict,
) -> bool:
    origin = headers.get("Origin")

    if not origin:
        return False

    return origin in ALLOWED_ORIGINS
