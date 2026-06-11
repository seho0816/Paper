import base64
import json
import jwt
import os


def decode_jws_payload(
    compact_token: str,
) -> dict:
    jws_verification_key = os.environ.get("JWS_VERIFICATION_KEY")
    if not jws_verification_key:
        raise ValueError("JWS_VERIFICATION_KEY environment variable not set. Cannot verify JWS token.")

    jws_allowed_algorithms_str = os.environ.get("JWS_ALLOWED_ALGORITHMS", "HS256")
    jws_allowed_algorithms = [alg.strip() for alg in jws_allowed_algorithms_str.split(',') if alg.strip()]
    if not jws_allowed_algorithms:
        raise ValueError("JWS_ALLOWED_ALGORITHMS environment variable is empty or invalid. Cannot verify JWS token.")

    try:
        payload = jwt.decode(
            jwt=compact_token,
            key=jws_verification_key,
            algorithms=jws_allowed_algorithms,
        )
        return payload
    except jwt.exceptions.PyJWTError as e:
        raise ValueError(f"Invalid or unverified JWS token: {e}") from e
