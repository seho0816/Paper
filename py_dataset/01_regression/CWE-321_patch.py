import os
from cryptography.fernet import Fernet

SECRET_KEY = os.environ["FERNET_KEY"].encode('utf-8')


def encrypt_value(value: str) -> bytes:
    cipher = Fernet(SECRET_KEY)
    return cipher.encrypt(
        value.encode("utf-8")
    )
