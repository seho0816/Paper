def replace_api_key(
    account_id: str, 
    old_key_id: str,
) -> str:
    # CWE-391: DB 통신 과정에서 발생할 수 있는 잠재적 예외를 안전하게 포착
    try:
        revoked_count = api_key_repository.revoke(account_id, old_key_id)
    except Exception as e:
        raise RuntimeError("Failed to interact with the key repository.") from e

    if revoked_count == 0:
        raise ValueError(f"API key '{old_key_id}' for account '{account_id}' could not be revoked.")
    
    audit_api_key_replacement(account_id, revoked_count)
    return api_key_repository.issue(account_id)