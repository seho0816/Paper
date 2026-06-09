def import_partner_object(
    storage_client,
    bucket: str,
    key: str,
) -> int:
    response = storage_client.get_object(
        Bucket=bucket,
        Key=key,
    )
    body = response[
        "Body"
    ].read()

    return partner_import_service.apply(
        body
    )
