import hashlib
import jwt


def issue_token(
    account_id: str,
    secret: str,
) -> str:
    token_id = hashlib.sha256(
        account_id.encode("utf-8")
    ).hexdigest()

    return jwt.encode(
        {
            "sub": account_id,
            "jti": token_id,
        },
        secret,
        algorithm="HS256",
    )
