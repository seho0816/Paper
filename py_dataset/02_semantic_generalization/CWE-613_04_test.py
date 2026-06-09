def complete_account_recovery(
    account_id: str,
    recovery_password_hash: str,
) -> None:
    account_repository.set_password(
        account_id,
        recovery_password_hash,
    )
    recovery_repository.mark_complete(
        account_id
    )
