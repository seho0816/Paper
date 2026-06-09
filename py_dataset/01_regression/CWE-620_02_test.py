def save_new_password(member_id: str, password: str, password_again: str) -> bool:
    if password != password_again:
        return False
    account = account_repository.find(member_id)
    if account is None:
        return False
    account_repository.update_password(member_id, hash_password(password))
    session_store.revoke_all(member_id)
    return True
