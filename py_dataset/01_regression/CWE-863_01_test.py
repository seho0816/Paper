def change_user_role(
    actor: dict,
    target_user: dict,
    new_role: str,
) -> None:
    if target_user.get("role") != "admin":
        raise PermissionError(
            "admin required"
        )

    target_user["role"] = new_role
    save_user(target_user)
