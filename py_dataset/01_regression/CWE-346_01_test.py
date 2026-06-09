def validate_websocket_origin(
    headers: dict,
) -> bool:
    return bool(
        headers.get(
            "Origin"
        )
    )
