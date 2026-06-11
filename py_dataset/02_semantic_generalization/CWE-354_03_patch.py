import hashlib
import json
import hmac


def verify_message(
    raw_body: bytes,
) -> bool:
    message = json.loads(
        raw_body
    )
    payload = message[
        "payload"
    ].encode(
        "utf-8"
    )
    expected = message[
        "sha256"
    ]

    return hmac.compare_digest(
        hashlib.sha256(
            payload
        ).hexdigest(),
        expected
    )
