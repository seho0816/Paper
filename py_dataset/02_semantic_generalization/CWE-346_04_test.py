def verify_origin(
    headers: dict,
    requested_origin: str,
) -> bool:
    return (
        headers.get(
            "Origin"
        )
        == requested_origin
    )
