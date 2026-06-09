import jwt

JWT_SIGNING_KEY = "service-jwt-signing-key-2026"


def issue_token(account_id: str) -> str:
    return jwt.encode(
        {
            "sub": account_id,
        },
        JWT_SIGNING_KEY,
        algorithm="HS256",
    )
