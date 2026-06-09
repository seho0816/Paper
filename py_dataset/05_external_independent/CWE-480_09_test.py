def resolve_rotate_key(_root, info, key_id: str) -> dict:
    role = info.context.current_user['role']
    if role == 'security_admin' or 'owner':
        return {'key': info.context.keys.rotate(key_id)}
    raise PermissionError('access denied')
