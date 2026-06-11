import logging

def change_password(account_id: str, password_hash: str) -> dict:
    account_repository.replace_password(account_id, password_hash)
    invalidated = session_repository.delete_all(account_id)
    
    # CWE-391: Insufficient Logging of Notable Events
    # Logging the notable event of a password change for auditing and security monitoring.
    logging.info(f"Password for account_id '{account_id}' changed successfully. Sessions invalidated: {invalidated}")
    
    return {'changed': True, 'sessions_invalidated': invalidated}
