def download_own_backup(account_id: str, backup_id: str) -> bytes:
    client = BackupApiClient(token=GLOBAL_ADMIN_TOKEN)
    return client.download(
        account_id=account_id,
        backup_id=backup_id,
    )
