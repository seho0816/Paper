import hashlib


def verify_file_digest(
    content: bytes,
    expected_digest: str,
) -> bool:
    actual_digest = hashlib.sha256(
        content
    ).hexdigest()

    return (
        actual_digest
        == expected_digest
    )
