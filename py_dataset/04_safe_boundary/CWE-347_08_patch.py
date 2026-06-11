import jwt


def decode_session_token(
    token: str,
    public_key: str,
) -> dict:
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        audience="account-service",
        issuer="identity-service",
    )

