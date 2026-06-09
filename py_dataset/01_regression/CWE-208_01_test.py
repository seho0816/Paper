def authenticate(
    email: str,
    password: str,
) -> bool:
    account = find_user_by_email(
        email
    )

    if account is None:
        return False

    return verify_password(
        password,
        account["password_hash"],
    )
