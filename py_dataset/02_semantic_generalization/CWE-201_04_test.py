def capture_failed_request(path: str, headers: dict, error: Exception) -> None:
    error_tracker.capture({
        "path": path,
        "headers": headers,
        "error": str(error),
    })
