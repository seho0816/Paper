import string

def update_password(
    account_id: str,
    password: str,
) -> None:
    # CWE-521: Weak Password Requirements
    # Strengthen password policy to include minimum length and character complexity requirements.

    min_length = 12 # Increased minimum length for better security
    if len(password) < min_length:
        raise ValueError(
            f"Password must be at least {min_length} characters long."
        )

    has_uppercase = any(c.isupper() for c in password)
    has_lowercase = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in string.punctuation for c in password)

    # Require at least one uppercase, one lowercase, one digit, and one special character.
    if not (has_uppercase and has_lowercase and has_digit and has_special):
        raise ValueError(
            "Password must contain at least one uppercase letter, "
            "one lowercase letter, one digit, and one special character."
        )

    # The store_new_password function is expected to securely hash the password
    # using a robust algorithm like bcrypt, argon2, or scrypt before storage.
    store_new_password(
        account_id,
        password,
    )
