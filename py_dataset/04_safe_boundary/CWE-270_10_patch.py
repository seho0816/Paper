from contextlib import contextmanager


security_context = {'user_id': None, 'role': 'guest'}


@contextmanager
def impersonate(user_id: str, role: str):
    previous = security_context.copy()
    try:
        security_context.update({'user_id': user_id, 'role': role})
        yield
    finally:
        security_context.clear()
        security_context.update(previous)


def rebuild_as_user(target_user_id: str) -> None:
    with impersonate(target_user_id, 'admin'):
        rebuild_user_cache(target_user_id)

