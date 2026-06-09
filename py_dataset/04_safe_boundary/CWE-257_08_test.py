from argon2 import PasswordHasher


hasher = PasswordHasher()


def store_password_hash(
    account_id: str,
    password: str,
) -> None:
    password_hash = hasher.hash(
        password
    )
    password_repository.save_hash(
        account_id,
        password_hash,
    )
