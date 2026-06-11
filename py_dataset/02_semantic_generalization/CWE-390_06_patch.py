def complete_sensitive_login(account_id: str, code: str) -> str:
    try:
        mfa_service.require_valid(account_id, code)
        return session_service.issue_privileged(account_id)
    except MfaVerificationError:
        login_metrics.record_failure(account_id)
        return ""
