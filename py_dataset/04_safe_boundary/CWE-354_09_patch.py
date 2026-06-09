import hashlib


def verify_uploaded_payload(
    payload: bytes,
    artifact_id: str,
) -> bool:
    trusted_digest = trusted_digest_store.load(
        artifact_id
    )
    actual_digest = hashlib.sha256(
        payload
    ).hexdigest()

    return (
        actual_digest
        == trusted_digest
    )

