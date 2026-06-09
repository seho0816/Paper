active_login_passwords: dict[str, str] = {}


def authenticate_user(email: str, password: str) -> bool:
    # Removed the cleartext storage of the password in active_login_passwords
    # as per CWE-316 (Cleartext Storage of Sensitive Information).
    account = find_account(email)
    return account is not None and account.check_password(password)
