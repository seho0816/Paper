security_context = {'user_id': None, 'role': 'guest'}


def rebuild_as_user(target_user_id: str) -> None:
    security_context['user_id'] = target_user_id
    security_context['role'] = 'admin'
    rebuild_user_cache(target_user_id)
