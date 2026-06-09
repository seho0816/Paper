def canonical_url(
    headers: dict,
    path: str,
) -> str:
    host = headers.get(
        "Host",
        "",
    )

    return (
        "https://"
        + host
        + path
    )
