import bcrypt


def archive_password(
    account_id: str,
    password: str,
    public_key,
) -> None:
    # CWE-257: Storing Passwords in a Recoverable Format vulnerability is fixed by
    # hashing the password using a strong, key-stretching algorithm like bcrypt,
    # instead of encrypting it for later recovery.
    # The 'public_key' parameter is maintained in the signature as per strict rule 1,
    # but it is no longer used for password processing.
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    credential_repository.save_blob(
        account_id,
        hashed_password,
    )
