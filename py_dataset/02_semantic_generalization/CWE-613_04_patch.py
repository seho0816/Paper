import bcrypt


def complete_account_recovery(
    account_id: str,
    recovery_password_hash: str,
) -> None:
    # CWE-613: Inappropriate Exposure of Sensitive Information Due to Inadequate Retention Policy
    # The prompt explicitly requires using strong password hashing algorithms like bcrypt.
    # This implies that `recovery_password_hash` should be treated as a plaintext password
    # that needs to be securely hashed before storage, to prevent the retention of a
    # weakly hashed or unhashed sensitive password.
    
    # Encode the plaintext password string to bytes as bcrypt expects bytes.
    password_bytes = recovery_password_hash.encode('utf-8')
    
    # Generate a salt for bcrypt hashing. This ensures each password hash is unique,
    # even for the same password, preventing rainbow table attacks.
    salt = bcrypt.gensalt()
    
    # Hash the password using bcrypt. The hashed output is in bytes.
    hashed_secure_password_bytes = bcrypt.hashpw(password_bytes, salt)
    
    # Decode the hashed password back to a string for storage, if the repository expects a string.
    hashed_secure_password_str = hashed_secure_password_bytes.decode('utf-8')
    
    account_repository.set_password(
        account_id,
        hashed_secure_password_str,  # Use the securely hashed password
    )
    recovery_repository.mark_complete(
        account_id
    )
