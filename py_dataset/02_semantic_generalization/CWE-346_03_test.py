from urllib.parse import urlparse


def allow_socket_origin(
    origin: str,
) -> bool:
    host = urlparse(
        origin
    ).hostname or ""

    return host.endswith(
        "example.com"
    )
