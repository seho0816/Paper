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

    # CWE-862: Missing Authorization
    # The current user has the 'users:suspend' capability, but it's crucial to verify
    # if they are authorized to suspend *this specific target user*.
    # This check prevents a user with the general 'users:suspend' scope from suspending
    # arbitrary users without proper privileges.

    user_id = current_user.get("id")
    user_roles = current_user.get("roles", [])

    is_admin = "admin" in user_roles
    is_self_suspension = (user_id is not None) and (str(user_id) == target_user_id)

    # If the current user is neither an administrator nor attempting to suspend themselves,
    # then they are not authorized to perform the action on the target_user_id.
    if not is_admin and not is_self_suspension:
        raise PermissionError(
            "unauthorized to suspend this user"
        )

    suspend_account(
        target_user_id,
    )
