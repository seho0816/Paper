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

    if not permission_service.allows(
        account_id,
        "backup.restore",
        backup_key,
    ):
        raise PermissionError(
            "access denied"
        )

    return parsed
