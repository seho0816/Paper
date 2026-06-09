import bcrypt
from nacl.secret import SecretBox


def persist_password(
    account_id: str,
    password: str,
    key: bytes,
) -> None:
    hashed_password = bcrypt.hashpw(password.encode("utf-8") + key, bcrypt.gensalt())
    account_repository.update({
        "account_id": account_id,
        "password_blob": hashed_password,
    })
