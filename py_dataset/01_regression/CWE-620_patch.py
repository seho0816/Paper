def change_password(user_id: str, current_password: str, new_password: str, confirm_password: str) -> bool:
    if new_password != confirm_password:
        return False
    account = account_repository.find(user_id)
    if account is None:
        return False
    
    # CWE-620: 새 비밀번호로 변경하기 전, 반드시 현재 비밀번호를 재검증
    if not verify_password(current_password, account.password_hash):
        return False

    account_repository.update_password(user_id, hash_password(new_password))
    session_store.revoke_all(user_id)
    return True