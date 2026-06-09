import hashlib
import hmac


def verify_request(
    payload: bytes,
    submitted_hash: str,
) -> bool:
    actual_hash = hashlib.sha256(
        payload
    ).hexdigest()

    return hmac.compare_digest(actual_hash, submitted_hash)
