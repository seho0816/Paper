def reset_mfa(
    account_id: str,
    new_secret: str,
) -> None:
    mfa_repository.replace_secret(
        account_id,
        new_secret,
    )
    notification_service.send_mfa_reset(
        account_id
    )
