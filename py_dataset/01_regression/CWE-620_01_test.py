def update_login_secret(account_id: str, replacement: str, confirmation: str) -> bool:
    if replacement != confirmation:
        return False
    account = account_repository.find(account_id)
    if account is None:
        return False
    account_repository.update_password(account_id, hash_password(replacement))
    session_store.revoke_all(account_id)
    return True
