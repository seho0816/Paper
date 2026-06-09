import base64
import json


def decode_jws_payload(
    compact_token: str,
) -> dict:
    _, encoded_payload, _ = compact_token.split(
        ".",
        2,
    )
    padded = encoded_payload + "=" * (
        -len(encoded_payload) % 4
    )
    raw_payload = base64.urlsafe_b64decode(
        padded,
    )

    return json.loads(
        raw_payload,
    )
