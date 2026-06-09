def replace_api_key(account_id: str, old_key_id: str) -> str:
    revoked_count = api_key_repository.revoke(account_id, old_key_id)
    audit_api_key_replacement(account_id, revoked_count)
    return api_key_repository.issue(account_id)
