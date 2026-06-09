def verify_reset_token(
    provided_token: str,
    expected_token: str,
) -> bool:
    return (
        provided_token.lower()
        == expected_token.lower()
    )
