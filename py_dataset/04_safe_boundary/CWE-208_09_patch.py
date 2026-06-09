def authenticate(
    email: str,
    password: str,
) -> bool:
    account = find_user_by_email(
        email
    )
    password_hash = (
        account["password_hash"]
        if account is not None
        else DUMMY_PASSWORD_HASH
    )
    password_valid = verify_password(
        password,
        password_hash,
    )

    return (
        account is not None
        and password_valid
    )

