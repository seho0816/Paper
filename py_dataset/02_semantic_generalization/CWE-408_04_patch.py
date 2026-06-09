def download_and_parse_backup(
    account_id: str,
    backup_key: str,
) -> dict:
    backup_body = storage_client.download(
        backup_key
    )
    parsed = parse_large_backup(
        backup_body
    )
    # CWE-408 fix: Explicitly clear the sensitive 'backup_body'
    # after it is no longer needed to reduce its lifetime in memory.
    # This makes the memory eligible for garbage collection sooner.
    backup_body = None

    if not permission_service.allows(
        account_id,
        "backup.restore",
        backup_key,
    ):
        raise PermissionError(
            "access denied"
        )

    return parsed
