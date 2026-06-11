import bcrypt


def hash_password(
    password: str,
) -> str:
    # Use bcrypt for password hashing, which includes salting and key stretching,
    # making it resistant to brute-force and rainbow table attacks.
    # bcrypt.hashpw takes bytes and returns bytes.
    hashed_bytes = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())
    # Decode the resulting bytes to a string for storage/return.
    return hashed_bytes.decode("utf-8")
