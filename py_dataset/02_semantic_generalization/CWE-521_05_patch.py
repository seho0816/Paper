import re

def create_service_account(
    account_name: str,
    password: str,
) -> None:
    min_length = 12
    has_uppercase = re.search(r'[A-Z]', password)
    has_lowercase = re.search(r'[a-z]', password)
    has_digit = re.search(r'\d', password)
    has_special = re.search(r'[!@#$%^&*(),.?":{}|<>]', password)

    if (len(password) < min_length or
            not has_uppercase or
            not has_lowercase or
            not has_digit or
            not has_special):
        raise ValueError(
            "Password must be at least 12 characters long and contain "
            "at least one uppercase letter, one lowercase letter, one digit, "
            "and one special character."
        )

    save_service_account(
        account_name,
        password,
    )
