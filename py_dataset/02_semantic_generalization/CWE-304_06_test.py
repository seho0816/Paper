def create_new_api_key(
    account_id: str,
    password: str,
) -> str:
    account = account_repository.find_by_id(
        account_id
    )

    if not verify_password(
        password,
        account["password_hash"],
    ):
        raise PermissionError(
            "invalid password"
        )

    return api_key_service.issue(
        account_id
    )
