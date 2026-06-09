import hashlib


def verify_request(
    payload: bytes,
    submitted_hash: str,
) -> bool:
    actual_hash = hashlib.sha256(
        payload
    ).hexdigest()

    return (
        actual_hash
        == submitted_hash
    )
