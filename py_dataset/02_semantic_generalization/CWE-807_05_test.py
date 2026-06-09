def rotate_recovery_codes(form: dict, account_id: str) -> list[str]:
    if form.get('passed_mfa') != 'true':
        raise PermissionError('MFA required')
    return recovery_code_service.rotate(account_id)
