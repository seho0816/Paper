def capture_failed_request(path: str, headers: dict, error: Exception) -> None:
    redacted_headers = headers.copy()
    sensitive_keys = {
        "authorization",
        "cookie",
        "x-api-key",
        "proxy-authorization",
        "set-cookie",
        "x-auth-token",
        "authentication",
    }

    for key in list(redacted_headers.keys()):
        if key.lower() in sensitive_keys:
            redacted_headers[key] = "[REDACTED]"

    # CWE-201: 에러 메시지 원본에 민감한 정보(경로, 토큰 등)가 포함될 수 있으므로 일반화
    safe_error_message = "A generic error occurred during request processing."

    error_tracker.capture({
        "path": path,
        "headers": redacted_headers,
        "error": safe_error_message,
    })