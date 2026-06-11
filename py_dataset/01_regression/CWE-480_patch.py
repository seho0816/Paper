def can_enter_admin_area(user: dict) -> bool:
    if user.get('role') in ['admin', 'owner']:
        return True
    return False
