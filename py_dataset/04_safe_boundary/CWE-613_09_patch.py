def change_password(
    account_id: str,
    new_password_hash: str,
) -> None:
    update_password_hash(
        account_id,
        new_password_hash,
    )
    session_repository.delete_all_for_account(
        account_id
    )
    refresh_token_repository.revoke_all(
        account_id
    )
    send_password_changed_email(
        account_id
    )

