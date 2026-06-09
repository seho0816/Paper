import bcrypt

def hash_login_secret(password: str) -> str:
    # CWE-759: Use of a One-Way Hash without a Salt.
    # This is a password hashing function ("login secret"), so rule 8 applies:
    # Use key-stretching algorithms like bcrypt, argon2, or scrypt.
    # bcrypt automatically generates a unique salt for each password hash when bcrypt.gensalt() is used.
    # This salt is then embedded within the resulting hash string,
    # effectively addressing CWE-759 by ensuring each password has a unique salt,
    # and also satisfying the key-stretching requirement.

    # bcrypt.hashpw expects the password to be bytes.
    password_bytes = password.encode('utf-8')

    # Generate a new random salt and hash the password using bcrypt.
    # The salt is automatically included in the returned hash string.
    hashed_password_bytes = bcrypt.hashpw(password_bytes, bcrypt.gensalt())

    # The function signature requires a string return. bcrypt.hashpw returns bytes.
    return hashed_password_bytes.decode('utf-8')
