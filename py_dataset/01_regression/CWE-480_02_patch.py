def can_login(account: dict) -> bool:
    status = account.get('status')
    if status != 'locked' and status != 'deleted':
        return True
    return False