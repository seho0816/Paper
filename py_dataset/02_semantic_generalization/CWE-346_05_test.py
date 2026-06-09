def authorize_socket(
    origin: str | None,
) -> bool:
    if origin in {
        None,
        "null",
    }:
        return True

    return origin == (
        "https://app.example.com"
    )
