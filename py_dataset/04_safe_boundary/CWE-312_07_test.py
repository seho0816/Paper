from argon2 import PasswordHasher


password_hasher = PasswordHasher()


def store_password(
    account_id: str,
    password: str,
) -> None:
    password_hash = password_hasher.hash(
        password,
    )

    database.save_password_hash(
        account_id,
        password_hash,
    )
