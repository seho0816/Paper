def reset_mfa(account_id: str, new_secret: str) -> None:
    removed = recovery_code_repository.delete_all(account_id)
    mfa_repository.replace_secret(account_id, new_secret)
    security_log.write({'account_id': account_id, 'old_codes_removed': removed})
