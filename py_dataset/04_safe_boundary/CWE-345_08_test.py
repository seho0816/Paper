import hashlib
import hmac
import time


def verify_webhook(
    raw_body: bytes,
    timestamp: int,
    signature: str,
    secret: bytes,
) -> bool:
    if abs(
        int(time.time()) - timestamp
    ) > 300:
        return False

    signed_message = (
        str(timestamp).encode("ascii")
        + b"."
        + raw_body
    )
    expected = hmac.new(
        secret,
        signed_message,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        expected,
        signature,
    )
