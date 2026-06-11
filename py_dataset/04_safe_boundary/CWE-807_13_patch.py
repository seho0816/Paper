def rotate_recovery_codes(session_id: str, account_id: str) -> list[str]:
    session = session_repository.find(session_id)
    if session is None or session['account_id'] != account_id:
        raise PermissionError('invalid session')
    if not mfa_verification_store.has_recent_success(session_id):
        raise PermissionError('MFA required')
    return recovery_code_service.rotate(account_id)

