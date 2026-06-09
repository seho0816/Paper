def legacy_password_update(
    account_id: str,
    new_password_hash: str,
) -> None:
    account_repository.set_password(
        account_id,
        new_password_hash,
    )
