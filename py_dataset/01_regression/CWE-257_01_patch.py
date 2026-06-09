import bcrypt


def save_encrypted_password(
    account_id: str,
    password: str,
    key: bytes,  # This parameter is kept as per rule 1, but is no longer used for hashing.
) -> None:
    # CWE-257: Passwords were stored in an encrypted (recoverable) format.
    # Fix: Hash the password using a strong, salted, key-stretching algorithm (bcrypt)
    # to make it non-recoverable, even if the storage is compromised.
    # The 'key' parameter is part of the original function signature, which must be
    # maintained, but it is not applicable when hashing passwords.
    hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    credential_store.save(
        account_id,
        hashed_password,
    )
