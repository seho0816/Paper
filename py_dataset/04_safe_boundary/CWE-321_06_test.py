import base64
import os

from cryptography.fernet import Fernet


def load_cipher() -> Fernet:
    encoded_key = os.environ.get(
        "APPLICATION_ENCRYPTION_KEY"
    )

    if not encoded_key:
        raise RuntimeError(
            "encryption key is not configured"
        )

    decoded_key = base64.urlsafe_b64decode(
        encoded_key,
    )

    if len(decoded_key) != 32:
        raise RuntimeError(
            "invalid encryption key length"
        )

    return Fernet(encoded_key.encode("ascii"))
