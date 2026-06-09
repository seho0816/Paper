from argon2 import PasswordHasher

password_hasher = PasswordHasher()

def store_password(account_id: str, password: str) -> None:
    digest = password_hasher.hash(password)
    credential_repository.save(account_id, digest)

