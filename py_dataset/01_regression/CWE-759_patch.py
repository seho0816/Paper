import bcrypt

def store_password(account_id: str, password: str) -> None:
    # Generate a salt for bcrypt. bcrypt.gensalt() creates a random salt.
    salt = bcrypt.gensalt()

    # Hash the password using bcrypt.hashpw.
    # bcrypt is a strong key derivation function (KDF) that internally handles salting
    # and key stretching, making it resistant to brute-force and rainbow table attacks.
    # The password must be encoded to bytes.
    hashed_password_bytes = bcrypt.hashpw(password.encode('utf-8'), salt)

    # bcrypt.hashpw returns bytes. Decode it to a string for storage,
    # consistent with the original hexdigest output which was a string.
    digest = hashed_password_bytes.decode('utf-8')

    # Store the account ID and the full hashed password (which includes the salt and cost factor).
    credential_repository.save(account_id, digest)
