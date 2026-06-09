import hashlib
import json


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

    return (
        hashlib.sha256(
            payload
        ).hexdigest()
        == expected
    )
