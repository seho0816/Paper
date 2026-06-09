def issue_login_token(
    username: str,
    password: str,
) -> str:
    account = account_repository.find(
        username
    )

    if (
        account is None
        or not verify_password(
            password,
            account["password_hash"],
        )
    ):
        raise PermissionError(
            "invalid credentials"
        )

    return token_service.issue(
        account["id"]
    )
