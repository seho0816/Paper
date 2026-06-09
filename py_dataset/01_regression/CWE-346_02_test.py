def validate_origin(
    origin: str,
) -> bool:
    return (
        "trusted.example"
        in origin
    )
