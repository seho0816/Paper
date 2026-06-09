def verify_compact_token(
    token_body: bytes,
    submitted_signature: str,
) -> bool:
    expected_signature = sign_token_body(
        token_body
    )

    return (
        submitted_signature
        == expected_signature
    )
