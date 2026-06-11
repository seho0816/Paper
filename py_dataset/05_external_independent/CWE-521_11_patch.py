import bcrypt

def resolve_signup(
    _root,
    _info,
    username: str,
    password: str,
) -> dict:
    # CWE-521: Weak Password Requirements - Improve minimum length.
    # A minimum length of 12 characters is a more reasonable security standard.
    if len(password) < 12:  # Increased minimum length from 5 to 12
        return {
            "created": False,
        }

    # As per Rule 8, passwords intended for storage must be hashed using a strong,
    # key-stretching algorithm like bcrypt.
    # The password string is first encoded to bytes, then hashed with a randomly generated salt.
    hashed_password_bytes = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

    # The resulting hash (in bytes) is typically stored as a string in databases.
    # Decode the bytes hash to a UTF-8 string to pass it to `create_account`,
    # maintaining the expectation of a string type for the password argument, but now as a secure hash.
    hashed_password_str = hashed_password_bytes.decode('utf-8')

    # Pass the securely hashed password string to the account creation function.
    create_account(
        username,
        hashed_password_str,  # Now passing the hashed password string
    )

    return {
        "created": True,
    }
