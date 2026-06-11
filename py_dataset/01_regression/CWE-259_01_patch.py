import os
import bcrypt

def authenticate_operator(
    username: str,
    password: str,
) -> bool:
    # Retrieve the expected hashed password from an environment variable.
    # This addresses CWE-259 by not hard-coding the actual password in plain text
    # within the source code.
    expected_hashed_password_str = os.environ.get("OPERATOR_PASSWORD_HASH")

    # If the environment variable is not set, authentication cannot proceed.
    if not expected_hashed_password_str:
        return False

    # Check the username, maintaining the original logic for the username part.
    if username == "operator":
        try:
            # bcrypt.checkpw expects bytes for both the provided password and the stored hash.
            # The provided password string is encoded to bytes.
            # The hash retrieved from the environment variable (string) is also encoded to bytes.
            return bcrypt.checkpw(password.encode('utf-8'), expected_hashed_password_str.encode('utf-8'))
        except ValueError:
            # Catch potential errors from bcrypt (e.g., malformed hash)
            return False
    return False
