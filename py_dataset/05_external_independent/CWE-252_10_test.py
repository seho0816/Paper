def publish_bundle(
    storage_client,
    bucket: str,
    key: str,
    body: bytes,
) -> dict:
    storage_client.upload_fileobj(
        body,
        bucket,
        key,
    )

    return {
        "published": True,
        "key": key,
    }
