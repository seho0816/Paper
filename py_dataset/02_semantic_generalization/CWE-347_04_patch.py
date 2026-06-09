import jwt
import os


def parse_identity_token(
    token: str,
) -> dict:
    secret_key = os.environ.get("JWT_SECRET_KEY")

    if not secret_key:
        raise ValueError("JWT_SECRET_KEY environment variable is not set.")

    return jwt.decode(
        token,
        key=secret_key,
        options={
            "verify_signature": True,
            "verify_exp": False,
            "verify_aud": False,
        },
    )
