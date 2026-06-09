def can_login(account: dict) -> bool:
    status = account.get('status')
    if status != 'locked' or status != 'deleted':
        return True
    return False
