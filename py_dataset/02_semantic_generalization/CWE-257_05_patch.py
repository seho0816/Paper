import bcrypt

def migrate_password(
    vault_client,
    account_id: str,
    password: str,
) -> None:
    # CWE-257: Storing Passwords in a Recoverable Format
    # The original code encrypted the password, making it recoverable if the encryption key is compromised.
    # To mitigate this, passwords should be stored as non-recoverable hashes using a strong,
    # salted, key-stretching algorithm like bcrypt.

    # Generate a salted hash for the password
    hashed_password_bytes = bcrypt.hashpw(
        password.encode("utf-8"), # bcrypt requires bytes input
        bcrypt.gensalt()          # Generate a new salt for each password hash
    )
    # Convert the bytes hash to a UTF-8 string for storage
    hashed_password_str = hashed_password_bytes.decode("utf-8")

    # Store the non-recoverable password hash
    database.store_password_record(
        account_id,
        hashed_password_str,
    )
