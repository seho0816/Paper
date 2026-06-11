def deactivate_account(
    account_id: str,
) -> None:
    account_repository.set_active(
        account_id,
        False,
    )
    # CWE-613: Insufficient Session Expiration
    # When an account is deactivated, any active sessions associated with it must be immediately invalidated
    # to prevent an attacker (or even the legitimate user) from continuing to use the account
    # through an existing, unexpired session.
    session_manager.invalidate_all_sessions_for_account(account_id)
    audit_account_deactivation(
        account_id
    )
