import hashlib
import hmac


def sign_message(
    secret: bytes,
    message: bytes,
) -> str:
    return hmac.new(
        secret,
        message,
        hashlib.sha256,
    ).hexdigest()

