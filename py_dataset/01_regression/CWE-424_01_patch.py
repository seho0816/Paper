import bcrypt

def legacy_password_update(
    account_id: str,
    new_password_hash: str,
) -> None:
    # CWE-424: Improper Protection of Alternate Path.
    # This function, being "legacy", implies it might have previously handled
    # password storage insecurely or accepted less secure hashes.
    # To ensure proper protection, the input 'new_password_hash' is treated
    # as the plaintext password and securely hashed using a strong,
    # key-stretching algorithm (bcrypt) before storage.
    
    # Generate a salt and hash the password using bcrypt.
    # bcrypt.hashpw expects bytes, so encode the string password.
    hashed_password_bytes = bcrypt.hashpw(new_password_hash.encode('utf-8'), bcrypt.gensalt())
    
    # Decode the resulting bytes to a string for storage, as databases typically store password hashes as strings.
    hashed_password_str = hashed_password_bytes.decode('utf-8')

    account_repository.set_password(
        account_id,
        hashed_password_str,
    )
