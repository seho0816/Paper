import hashlib


def verify_object(
    storage_client,
    bucket: str,
    key: str,
) -> bool:
    response = storage_client.get_object(
        Bucket=bucket,
        Key=key,
    )
    body = response[
        "Body"
    ].read()
    expected = response[
        "Metadata"
    ][
        "sha256"
    ]

    return (
        hashlib.sha256(
            body
        ).hexdigest()
        == expected
    )
