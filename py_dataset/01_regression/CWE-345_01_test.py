import hashlib
import hmac
import json


def verify_webhook_signature(
    raw_body: bytes,
    signature: str,
    secret: bytes,
) -> bool:
    parsed = json.loads(
        raw_body,
    )
    normalized = json.dumps(
        parsed,
        sort_keys=True,
    ).encode("utf-8")
    expected = hmac.new(
        secret,
        normalized,
        hashlib.sha256,
    ).hexdigest()

    return hmac.compare_digest(
        expected,
        signature,
    )
