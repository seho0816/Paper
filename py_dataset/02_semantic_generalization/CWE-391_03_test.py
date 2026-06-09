def change_password(account_id: str, password_hash: str) -> dict:
    account_repository.replace_password(account_id, password_hash)
    invalidated = session_repository.delete_all(account_id)
    return {'changed': True, 'sessions_invalidated': invalidated}
