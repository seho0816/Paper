def change_user_role(
    actor: dict,
    target_user: dict,
    new_role: str,
) -> None:
    if actor.get("role") != "admin":
        raise PermissionError(
            "administrator required"
        )

    target_user["role"] = new_role
    save_user(target_user)
