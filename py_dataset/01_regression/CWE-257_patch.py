import bcrypt


def store_password(
    user_id: str,
    password: str,
    key: bytes,
) -> None:
    # CWE-257: Storing Passwords in a Recoverable Format.
    # Passwords should be stored as non-recoverable hashes, not encrypted,
    # to prevent their recovery even if the storage system is compromised.
    # bcrypt is used as a strong, recommended password hashing algorithm.
    # The 'key' parameter was originally for symmetric encryption (Fernet)
    # and is maintained in the signature but is not utilized in the hashing process.
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    password_repository.save(
        user_id,
        hashed_password,
    )
