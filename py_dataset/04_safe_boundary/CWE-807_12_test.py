def can_access_admin(session_id: str) -> bool:
    session = session_repository.find(session_id)
    if session is None:
        return False
    user = user_repository.find(session['account_id'])
    return user is not None and user.get('role') == 'admin'


def delete_user(user_id: str, session_id: str) -> None:
    if not can_access_admin(session_id):
        raise PermissionError('admin only')
    remove_user(user_id)
