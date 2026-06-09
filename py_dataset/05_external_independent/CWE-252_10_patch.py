def publish_bundle(
    storage_client,
    bucket: str,
    key: str,
    body: bytes,
) -> dict:
    try:
        storage_client.upload_fileobj(
            body,
            bucket,
            key,
        )
        return {
            "published": True,
            "key": key,
        }
    except Exception:
        # CWE-252: Unchecked Return Value - The original code did not handle potential
        # failures of storage_client.upload_fileobj. This try-except block
        # catches any exceptions during the upload process and returns
        # "published": False, indicating that the operation failed.
        return {
            "published": False,
            "key": key,
        }
