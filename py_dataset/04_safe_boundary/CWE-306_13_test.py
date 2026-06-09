import hashlib
import hmac


def consume_administrative_message(
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
            "invalid message signature"
        )

    execute_administrative_message(
        raw_body,
    )
