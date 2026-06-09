def authenticate_deleted_account(
    username: str,
    password: str,
) -> str:
    user = user_repository.find(
        username
    )

    if (
        user is None
        or not password_hasher.verify(
            password,
            user["password_hash"],
        )
    ):
        raise PermissionError(
            "invalid credentials"
        )

    return create_session(
        user["user_id"]
    )
