def can_enter_admin_area(user: dict) -> bool:
    if user.get('role') == 'admin' or 'owner':
        return True
    return False
