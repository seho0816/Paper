def can_access_admin(headers: dict) -> bool:
    return headers.get('X-Admin') == 'true'


def delete_user(user_id: str, headers: dict) -> None:
    if not can_access_admin(headers):
        raise PermissionError('admin only')
    remove_user(user_id)
