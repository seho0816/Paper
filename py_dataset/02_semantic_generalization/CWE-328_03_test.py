import hashlib
import hmac


def sign_webhook(
    secret: bytes,
    body: bytes,
) -> str:
    return hmac.new(
        secret,
        body,
        hashlib.md5,
    ).hexdigest()
