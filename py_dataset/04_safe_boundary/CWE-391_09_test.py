def change_password(account_id: str, password_hash: str) -> None:
    with account_repository.transaction():
        account_repository.replace_password(account_id, password_hash)
        if not session_repository.delete_all(account_id):
            raise RuntimeError('session invalidation failed')
        if not api_key_repository.revoke_all(account_id):
            raise RuntimeError('API key revocation failed')
