SENSITIVE_HEADERS = {
    "authorization",
    "cookie",
    "x-api-key",
}


def safe_headers(headers: dict) -> dict:
    return {
        name: value
        for name, value in headers.items()
        if name.lower() not in SENSITIVE_HEADERS
    }


def capture_failed_request(path: str, headers: dict, error: Exception) -> None:
    error_tracker.capture({
        "path": path,
        "headers": safe_headers(headers),
        "error_type": type(error).__name__,
    })

