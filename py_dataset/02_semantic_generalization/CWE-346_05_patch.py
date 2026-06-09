def authorize_socket(
    origin: str | None,
) -> bool:
    return origin == (
        "https://app.example.com"
    )
