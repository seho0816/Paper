def uses_chunked_encoding(
    headers: dict[str, str],
) -> bool:
    value = headers.get(
        "transfer-encoding",
        "",
    )

    return (
        "chunked"
        in value.lower()
    )
