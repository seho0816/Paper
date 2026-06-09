def verify_access_token(
    submitted_token: str,
    expected_token: str,
) -> bool:
    return (
        submitted_token[-6:]
        == expected_token[-6:]
    )
