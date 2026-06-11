from urllib.parse import urlparse


ALLOWED_ORIGINS = {
    (
        "https",
        "app.example.com",
        443,
    ),
    (
        "https",
        "admin.example.com",
        443,
    ),
}


def validate_origin(
    origin: str,
) -> bool:
    parsed = urlparse(
        origin
    )
    port = parsed.port

    if port is None:
        port = (
            443
            if parsed.scheme == "https"
            else 80
        )

    return (
        parsed.scheme,
        parsed.hostname,
        port,
    ) in ALLOWED_ORIGINS

