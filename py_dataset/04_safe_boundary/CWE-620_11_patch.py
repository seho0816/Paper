def change_password(
    actor_id: str,
    current_password: str,
    new_password: str,
    confirmation: str,
) -> bool:
    if new_password != confirmation:
        return False
    account = account_repository.get_active(actor_id)
    if account is None:
        return False
    if not password_hasher.verify(current_password, account.password_hash):
        return False
    account_repository.update_password(actor_id, password_hasher.hash(new_password))
    session_store.revoke_all_except_current(actor_id)
    return True

