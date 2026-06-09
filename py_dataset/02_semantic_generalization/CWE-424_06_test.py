def mobile_change_email(
    account_id: str,
    new_email: str,
) -> None:
    account_repository.update_email(
        account_id,
        new_email,
    )
