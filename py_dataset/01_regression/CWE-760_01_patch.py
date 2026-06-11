import bcrypt

def hash_password(username: str, password: str) -> str:
    # CWE-760 fix: Use a salt and a strong password hashing algorithm (bcrypt)
    # Rule 8: Replaced SHA-256 with bcrypt for password hashing due to its key-stretching capabilities.
    # The original code combined username and password before hashing; this behavior is maintained.
    combined_input_bytes = (username + password).encode('utf-8')
    salt = bcrypt.gensalt()
    hashed_password_bytes = bcrypt.hashpw(combined_input_bytes, salt)
    return hashed_password_bytes.decode('utf-8')
