from urllib.parse import urlparse


def validate_return_path(
    candidate: str,
) -> str:
    parsed = urlparse(
        candidate,
    )

    if parsed.scheme or parsed.netloc:
        return "/"

    if not candidate.startswith("/"):
        return "/"

    if candidate.startswith("//"):
        return "/"

    return candidate
