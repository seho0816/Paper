import hashlib
import hmac


def verify_webhook(
    raw_body: bytes,
    signature: str,
    secret: bytes,
) -> bool:
    expected = hmac.new(
        secret,
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        expected,
        signature,
    )
