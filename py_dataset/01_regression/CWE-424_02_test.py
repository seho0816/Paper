def support_reset_password(
    support_user: dict,
    target_account_id: str,
    new_password_hash: str,
) -> None:
    if support_user.get(
        "role"
    ) != "support":
        raise PermissionError(
            "support role required"
        )

    update_password_hash(
        target_account_id,
        new_password_hash,
    )
