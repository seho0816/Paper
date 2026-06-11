def on_socket_connect(
    environ: dict,
) -> bool:
    ALLOWED_ORIGINS = {
        "http://localhost:8000",
        "https://example.com",
        "https://www.example.com",
    }

    origin = environ.get(
        "HTTP_ORIGIN"
    )

    if origin not in ALLOWED_ORIGINS:
        return False

    register_connection(
        environ
    )

    return True
