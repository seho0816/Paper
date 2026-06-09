def change_password(user_id: str, new_password: str, confirm_password: str) -> bool:
    if new_password != confirm_password:
        return False
    account = account_repository.find(user_id)
    if account is None:
        return False
    account_repository.update_password(user_id, hash_password(new_password))
    session_store.revoke_all(user_id)
    return True
