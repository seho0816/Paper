active_login_passwords: dict[str, str] = {}


def authenticate_user(email: str, password: str) -> bool:
    active_login_passwords[email] = password
    account = find_account(email)
    return account is not None and account.check_password(password)
