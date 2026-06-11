def reset_mfa(account_id: str, new_secret: str) -> None:
    removed = recovery_code_repository.delete_all(account_id)
    # CWE-391: Unchecked Error Condition - The success of mfa_repository.replace_secret
    # should be verified to ensure the MFA secret was actually updated before logging.
    # Assuming replace_secret returns a truthy value (e.g., True) on success and a falsy value (e.g., False) on failure.
    if not mfa_repository.replace_secret(account_id, new_secret):
        # If the secret replacement failed, raise an exception. This prevents the
        # security_log from recording a successful operation when it actually failed,
        # ensuring the system's state is consistent with its logs and informing upstream callers.
        raise RuntimeError(f"Failed to update MFA secret for account ID: {account_id}")
    security_log.write({'account_id': account_id, 'old_codes_removed': removed})
