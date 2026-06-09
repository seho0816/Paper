def persist_export(
    destination: str,
    content: bytes,
) -> str:
    storage_client.put(
        destination,
        content,
    )

    return destination
