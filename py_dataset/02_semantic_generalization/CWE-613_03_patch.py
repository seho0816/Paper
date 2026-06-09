def reset_mfa(
    account_id: str,
    new_secret: str,
) -> None:
    mfa_repository.replace_secret(
        account_id,
        new_secret,
    )
    # Invalidate all active user sessions after a security-sensitive event like MFA reset
    # to mitigate CWE-613: Insufficient Session Expiration.
    session_service.invalidate_all_sessions(account_id)
    notification_service.send_mfa_reset(
        account_id
    )
