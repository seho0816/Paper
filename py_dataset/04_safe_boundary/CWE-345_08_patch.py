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

    # CWE-345: Insufficient Verification of Data Authenticity
    # The signature string provided by the client might use uppercase hexadecimal
    # characters, while hmac.hexdigest() generates lowercase characters.
    # To ensure robust verification, the incoming signature should be canonicalized
    # (e.g., converted to lowercase) before comparison.
    return hmac.compare_digest(
        expected,
        signature.lower(),
    )
