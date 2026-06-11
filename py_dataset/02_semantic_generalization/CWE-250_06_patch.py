def download_own_backup(account_id: str, backup_id: str) -> bytes:
    # CWE-250: Execution with Unnecessary Privileges
    # The function 'download_own_backup' implies downloading a backup for the authenticated user's own account.
    # Using 'GLOBAL_ADMIN_TOKEN' grants unnecessary and excessive privileges, allowing potential
    # access to any account's backup if 'account_id' is controlled by an attacker.
    # To fix this, the BackupApiClient should be initialized without an explicit admin token,
    # allowing it to rely on the current user's authenticated context or a user-specific token
    # to enforce least privilege. It's assumed BackupApiClient can retrieve the appropriate
    # user-specific token from the environment or execution context if 'token' is not provided.
    client = BackupApiClient()
    return client.download(
        account_id=account_id,
        backup_id=backup_id,
    )
