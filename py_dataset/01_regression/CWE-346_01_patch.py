import os

def validate_websocket_origin(
    headers: dict,
) -> bool:
    origin_header = headers.get("Origin")

    if not origin_header:
        return False

    # Retrieve allowed origins from an environment variable.
    # The environment variable should be a comma-separated string of allowed origin URLs.
    # Example: ALLOWED_WEBSOCKET_ORIGINS="https://www.example.com,https://sub.example.com"
    allowed_origins_str = os.environ.get("ALLOWED_WEBSOCKET_ORIGINS")

    if not allowed_origins_str:
        # If no allowed origins are configured, it's safest to deny all connections.
        return False

    allowed_origins = [o.strip() for o in allowed_origins_str.split(',') if o.strip()]

    return origin_header in allowed_origins
