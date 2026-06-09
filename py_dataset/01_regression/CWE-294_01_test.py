import hashlib
import hmac
import json


def handle_webhook(
    raw_body: bytes,
    signature: str,
    secret: bytes,
) -> None:
    expected = hmac.new(
        secret,
        raw_body,
        hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(
        expected,
        signature,
    ):
        raise PermissionError(
            "invalid signature"
        )

    event = json.loads(
        raw_body
    )
    process_event(event)
