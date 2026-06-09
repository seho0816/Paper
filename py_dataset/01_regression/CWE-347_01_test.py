import jwt


def decode_session_token(
    token: str,
    public_key: str,
) -> dict:
    header = jwt.get_unverified_header(
        token,
    )
    algorithm = header.get("alg")

    return jwt.decode(
        token,
        public_key,
        algorithms=[algorithm],
    )
