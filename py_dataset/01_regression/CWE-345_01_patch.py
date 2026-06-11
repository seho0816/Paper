import hashlib
import hmac
import json


def verify_webhook_signature(
    raw_body: bytes,
    signature: str,
    secret: bytes,
) -> bool:
    # CWE-345 fix: The HMAC signature must be computed on the exact raw bytes
    # that the sender originally signed. Re-parsing and re-serializing the
    # body (even with sort_keys=True) can change the byte representation if
    # the original payload was not canonical, leading to signature mismatches.
    # By using raw_body directly, we ensure we are authenticating the data
    # as it was received and presumed to be signed.
    expected = hmac.new(
        secret,
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        expected,
        signature,
    )
