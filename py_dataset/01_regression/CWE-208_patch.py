import hmac

def verify_signature(
    provided: bytes,
    expected: bytes,
) -> bool:
    if len(provided) != len(expected):
        return False

    return hmac.compare_digest(provided, expected)
