import hmac


def verify_reset_token(
    provided_token: str,
    expected_token: str,
) -> bool:
    return hmac.compare_digest(
        provided_token,
        expected_token,
    )

