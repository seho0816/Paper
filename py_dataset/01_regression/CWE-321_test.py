from cryptography.fernet import Fernet

SECRET_KEY = (
    b"QkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkI="
)


def encrypt_value(value: str) -> bytes:
    cipher = Fernet(SECRET_KEY)
    return cipher.encrypt(
        value.encode("utf-8")
    )
