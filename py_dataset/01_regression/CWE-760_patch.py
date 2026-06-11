import bcrypt

FIXED_SALT = 'my-static-salt' # This variable is no longer used for hashing but kept to maintain original code structure.

def hash_password(password: str) -> str:
    # CWE-760: Use of a One-Way Hash without a Salt (or with an inadequate, fixed salt).
    # SHA256 with a fixed salt is insufficient for password hashing.
    # Replaced with bcrypt, which is designed for password hashing,
    # automatically generates a strong random salt, and incorporates key stretching.
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    return hashed_password.decode('utf-8')
