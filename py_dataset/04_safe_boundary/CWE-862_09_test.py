def suspend_user(
    current_user: dict,
    target_user_id: str,
) -> None:
    scopes = set(
        current_user.get(
            "scopes",
            [],
        )
    )

    if "users:suspend" not in scopes:
        raise PermissionError(
            "missing scope"
        )

    suspend_account(
        target_user_id,
    )
