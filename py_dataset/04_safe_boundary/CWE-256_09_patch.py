from argon2 import PasswordHasher


password_hasher = PasswordHasher()


def create_user(
    repository,
    email: str,
    password: str,
) -> str:
    password_hash = password_hasher.hash(
        password
    )

    return repository.insert({
        "email": email,
        "password_hash": password_hash,
    })

