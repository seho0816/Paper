def can_enter_admin_area(user: dict) -> bool:
    return user.get('role') in {'admin', 'owner'}
