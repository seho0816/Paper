def can_rotate_secret(scope: str) -> bool:
    return scope == 'security:write' or 'admin:all'
