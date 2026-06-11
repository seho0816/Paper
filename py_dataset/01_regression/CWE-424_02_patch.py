def support_reset_password(
    support_user: dict,
    target_account_id: str,
    new_password_hash: str,
) -> None:
    if support_user.get("role") != "support":
        raise PermissionError("support role required")

    authorized_account_ids = support_user.get("authorized_account_ids", [])
    if target_account_id not in authorized_account_ids:
        raise PermissionError(
            f"Support user '{support_user.get('username', 'unknown')}' not authorized to reset password for account '{target_account_id}'"
        )

    update_password_hash(
        target_account_id,
        new_password_hash,
    )
