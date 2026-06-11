async def proxy_request(
    scope: dict,
    receive,
    send_backend,
) -> None:
    body_parts = []

    while True:
        message = await receive()
        body_parts.append(
            message.get(
                "body",
                b"",
            )
        )

        if not message.get(
            "more_body",
            False,
        ):
            break

    # Fix for CWE-444: Inconsistent Interpretation of HTTP Requests (HTTP Request Smuggling)
    # Remove potentially conflicting or malicious Transfer-Encoding and Content-Length headers
    # from the incoming request (scope["headers"]) and add a new, accurate Content-Length header
    # based on the actual body being forwarded to ensure consistent interpretation by the backend.
    
    sanitized_headers = []
    # Headers that could lead to smuggling if inconsistent
    headers_to_filter_out = {b"content-length", b"transfer-encoding"}

    for name, value in scope["headers"]:
        # Filter out problematic headers, preserving others
        if name.lower() not in headers_to_filter_out:
            sanitized_headers.append((name, value))
            
    full_body = b"".join(body_parts)
    
    # Add an accurate Content-Length header based on the actual assembled body.
    # This overrides any Content-Length that might have been present (or missing)
    # in the original request and ensures the backend receives a consistent length.
    sanitized_headers.append((b"content-length", str(len(full_body)).encode("ascii")))

    await send_backend(
        headers=sanitized_headers,
        body=full_body,
    )
