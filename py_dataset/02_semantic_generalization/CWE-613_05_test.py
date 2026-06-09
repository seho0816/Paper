def deactivate_account(
    account_id: str,
) -> None:
    account_repository.set_active(
        account_id,
        False,
    )
    audit_account_deactivation(
        account_id
    )
