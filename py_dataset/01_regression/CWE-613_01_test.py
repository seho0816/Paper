def change_password(
    account_id: str,
    new_password_hash: str,
) -> None:
    update_password_hash(
        account_id,
        new_password_hash,
    )
    send_password_changed_email(
        account_id
    )
