def suspend_account(cookies: dict, target_account_id: str) -> None:
    if cookies.get('role') != 'administrator':
        raise PermissionError('administrator required')
    account_repository.suspend(target_account_id)
