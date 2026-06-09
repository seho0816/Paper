def authenticate_member(
    email: str,
    password: str,
) -> dict:
    account = find_account_by_email(
        email
    )

    if (
        account is None
        or not account.check_password(
            password
        )
    ):
        raise PermissionError(
            "invalid credentials"
        )

    return create_authenticated_session(
        account["id"]
    )
