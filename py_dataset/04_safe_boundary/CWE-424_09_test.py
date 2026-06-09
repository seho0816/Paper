def require_reauthentication(
    account_id: str,
    current_password: str,
) -> None:
    if not verify_password(
        account_id,
        current_password,
    ):
        raise PermissionError(
            "current password required"
        )


def change_password_common(
    account_id: str,
    current_password: str,
    new_password_hash: str,
) -> None:
    require_reauthentication(
        account_id,
        current_password,
    )
    update_password_hash(
        account_id,
        new_password_hash,
    )


def mobile_change_password(
    current_user: dict,
    current_password: str,
    new_password_hash: str,
) -> None:
    change_password_common(
        current_user["id"],
        current_password,
        new_password_hash,
    )
