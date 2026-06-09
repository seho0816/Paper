import hashlib
import hmac


def verify_webhook(
    body: bytes,
    timestamp: str,
    signature: str,
    secret: bytes,
) -> bool:
    expected = hmac.new(
        secret,
        body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        expected,
        signature,
    )
