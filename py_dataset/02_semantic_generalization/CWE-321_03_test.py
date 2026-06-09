import hashlib
import hmac

MESSAGE_AUTHENTICATION_KEY = (
    b"shared-message-authentication-key"
)


def sign_message(message: bytes) -> str:
    return hmac.new(
        MESSAGE_AUTHENTICATION_KEY,
        message,
        hashlib.sha256,
    ).hexdigest()
