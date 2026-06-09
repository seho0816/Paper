import hmac


def verify_signature(
    provided: bytes,
    expected: bytes,
) -> bool:
    return hmac.compare_digest(
        provided,
        expected,
    )
