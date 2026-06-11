import os
import bcrypt

ADMIN_USERNAME = "admin"


def check_admin_login(
    username: str,
    password: str,
) -> bool:
    try:
        # The hard-coded password is removed.
        # The bcrypt hash of the admin password must be stored in an environment variable.
        # This ensures the password itself is not in the codebase (CWE-259 fix).
        admin_password_hash_env = os.environ["ADMIN_PASSWORD_HASH"]
    except KeyError:
        # If the environment variable is not set, login cannot proceed.
        # This signals a configuration error and prevents insecure operation.
        return False

    if username != ADMIN_USERNAME:
        return False

    try:
        # Verify the provided cleartext password against the stored bcrypt hash.
        # Both the input password and the stored hash (from env var) need to be bytes.
        return bcrypt.checkpw(password.encode('utf-8'), admin_password_hash_env.encode('utf-8'))
    except ValueError:
        # This handles cases where the fetched hash might be malformed or invalid bcrypt format.
        return False
