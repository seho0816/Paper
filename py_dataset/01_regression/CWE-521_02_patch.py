import re

def change_password(
    account_id: str,
    new_password: str,
) -> bool:
    # CWE-521: Weak Password Requirements.
    # The original code only required the password to be numeric, which is extremely weak.
    # This fix enforces a stronger password policy:
    # - Minimum length of 12 characters.
    # - Contains at least one uppercase letter.
    # - Contains at least one lowercase letter.
    # - Contains at least one digit.
    # - Contains at least one special character.
    if len(new_password) < 12:
        return False
    if not re.search(r"[A-Z]", new_password):
        return False
    if not re.search(r"[a-z]", new_password):
        return False
    if not re.search(r"\d", new_password):
        return False
    if not re.search(r"[!@#$%^&*()_+\-=\[\]{}|;':\",.<>/?`~]", new_password):
        return False

    # Assuming save_password function handles secure hashing (e.g., using bcrypt, argon2).
    # The plain-text password is passed here, but it should be hashed by save_password.
    save_password(
        account_id,
        new_password,
    )

    return True
