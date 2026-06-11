import hashlib
import hmac


def sign_webhook(
    secret: bytes,
    body: bytes,
) -> str:
    return hmac.new(
        secret,
        body,
        hashlib.sha256,  # CWE-328: Replaced MD5 with SHA256 for stronger cryptographic security.
    ).hexdigest()
