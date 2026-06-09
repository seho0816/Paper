import re

def register_account(
    username: str,
    password: str,
) -> None:
    # CWE-521: Weak Password Requirements.
    # The original code only checked for a minimum length of 6 characters, which is insufficient.
    # This patch implements stronger password requirements:
    # 1. Minimum length of 12 characters.
    # 2. Must contain at least one uppercase letter.
    # 3. Must contain at least one lowercase letter.
    # 4. Must contain at least one digit.
    # 5. Must contain at least one special character (non-alphanumeric).

    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long.")

    if not re.search(r"[A-Z]", password):
        raise ValueError("Password must contain at least one uppercase letter.")

    if not re.search(r"[a-z]", password):
        raise ValueError("Password must contain at least one lowercase letter.")

    if not re.search(r"\d", password):
        raise ValueError("Password must contain at least one digit.")

    # Checks for at least one special character (any non-alphanumeric character).
    if not re.search(r"[^A-Za-z0-9]", password):
        raise ValueError("Password must contain at least one special character.")

    # The create_account function is assumed to handle secure password hashing
    # (e.g., using bcrypt, argon2, or scrypt) internally as per best practices.
    create_account(
        username,
        password,
    )
