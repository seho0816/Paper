def mobile_change_password(
    current_user: dict,
    new_password_hash: str,
) -> None:
    update_password_hash(
        current_user["id"],
        new_password_hash,
    )
