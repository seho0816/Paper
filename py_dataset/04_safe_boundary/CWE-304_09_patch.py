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

    if (
        not account["is_active"]
        or account.get(
            "locked_at"
        ) is not None
        or account.get(
            "deleted_at"
        ) is not None
        or account.get(
            "approval_status"
        ) != "approved"
    ):
        raise PermissionError(
            "account unavailable"
        )

    return create_authenticated_session(
        account["id"]
    )

