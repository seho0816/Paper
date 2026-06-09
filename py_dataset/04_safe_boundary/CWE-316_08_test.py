def authenticate_user(email: str, password: str) -> bool:
    account = find_account(email)
    if account is None:
        return False
    return account.check_password(password)
