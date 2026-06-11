def import_partner_object(
    storage_client,
    bucket: str,
    key: str,
) -> int:
    response = storage_client.get_object(
        Bucket=bucket,
        Key=key,
    )
    # CWE-353: Ensure the streaming body is properly closed to prevent resource leaks.
    # The 'Body' object (e.g., botocore.response.StreamingBody) should be handled
    # as a resource that needs explicit closure or a context manager for reliable release.
    with response["Body"] as body_stream:
        body = body_stream.read()

    return partner_import_service.apply(
        body
    )
