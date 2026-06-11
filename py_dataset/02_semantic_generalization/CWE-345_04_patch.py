import hashlib
import hmac


def verify_webhook(
    body: bytes,
    timestamp: str,
    signature: str,
    secret: bytes,
) -> bool:
    # CWE-345: Insufficient Verification of Data Authenticity
    # The timestamp is passed but not used in the signature calculation,
    # which could allow for replay attacks.
    # To fix this, include the timestamp in the data that is signed.
    # A common pattern is to concatenate the timestamp (encoded to bytes) with the request body.
    signed_payload = timestamp.encode('utf-8') + body
    expected = hmac.new(
        secret,
        signed_payload,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        expected,
        signature,
    )
