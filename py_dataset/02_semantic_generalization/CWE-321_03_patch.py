import hashlib
import hmac
import os

_hmac_key_string = os.environ.get("HMAC_SIGNING_KEY")
if not _hmac_key_string:
    raise ValueError("HMAC_SIGNING_KEY environment variable is not set.")

MESSAGE_AUTHENTICATION_KEY = _hmac_key_string.encode('utf-8')


def sign_message(message: bytes) -> str:
    return hmac.new(
        MESSAGE_AUTHENTICATION_KEY,
        message,
        hashlib.sha256,
    ).hexdigest()
