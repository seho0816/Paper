from cryptography.fernet import Fernet


def store_password(
    user_id: str,
    password: str,
    key: bytes,
) -> None:
    cipher = Fernet(
        key
    )
    encrypted_password = cipher.encrypt(
        password.encode("utf-8")
    )
    password_repository.save(
        user_id,
        encrypted_password,
    )
