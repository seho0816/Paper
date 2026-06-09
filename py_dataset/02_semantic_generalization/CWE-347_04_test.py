import jwt


def parse_identity_token(
    token: str,
) -> dict:
    return jwt.decode(
        token,
        key=None,
        options={
            "verify_signature": False,
            "verify_exp": False,
            "verify_aud": False,
        },
    )
