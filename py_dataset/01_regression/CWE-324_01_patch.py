import os

def issue_token(
    account_id: str,
    signing_key: dict,
) -> str:
    return encode_jwt(
        {
            "sub": account_id,
        },
        os.environ["JWT_SIGNING_SECRET"],
        headers={
            "kid": signing_key["kid"],
        },
    )
