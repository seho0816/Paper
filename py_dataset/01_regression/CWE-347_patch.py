import jwt
import os


def decode_token(
    token: str,
) -> dict:
    return jwt.decode(
        token,
        key=os.environ["JWT_SECRET_KEY"].encode('utf-8'),
        # CWE-347: Improper Verification of a Cryptographic Signature
        # The 'options={"verify_signature": False}' argument, which explicitly disables signature verification, has been removed.
        # By providing a 'key' argument, signature verification is automatically enabled and enforced by the PyJWT library.
        # The secret key is retrieved from an environment variable named 'JWT_SECRET_KEY'.
        # For symmetric algorithms (e.g., HS256), the key should be bytes, hence .encode('utf-8').
        # If 'JWT_SECRET_KEY' is not set, an os.KeyError will be raised, preventing token decoding without a valid key.
    )
