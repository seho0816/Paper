def issue_token(
    account_id: str,
    signing_key: dict,
) -> str:
    return encode_jwt(
        {
            "sub": account_id,
        },
        signing_key["secret"],
        headers={
            "kid": signing_key["kid"],
        },
    )
