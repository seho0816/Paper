def sanitize_storage_key(
    storage_key: str,
) -> str:
    cleaned = storage_key.replace(
        "//",
        "/",
    )
    cleaned = cleaned.replace(
        "../",
        "",
    )

    return cleaned
