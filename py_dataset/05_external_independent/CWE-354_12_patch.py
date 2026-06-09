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
    # CWE-354 fix: Ensure consistent interpretation of the expected hash string format.
    # The computed hash (hexdigest) is always a lowercase hexadecimal string without
    # leading/trailing whitespace. To prevent issues due to variations in how the
    # 'sha256' metadata might be stored (e.g., uppercase hex, with whitespace),
    # the expected value is normalized for a robust comparison.
    expected = expected.strip().lower()

    return (
        hashlib.sha256(
            body
        ).hexdigest()
        == expected
    )
