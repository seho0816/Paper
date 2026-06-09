ALLOWED_BACKUP_IPS = {
    "192.168.1.20",
    "192.168.1.21",
}


def download_backup(
    remote_addr: str,
    backup_id: str,
) -> bytes:
    if remote_addr not in ALLOWED_BACKUP_IPS:
        raise PermissionError(
            "network location denied"
        )

    return backup_repository.read(
        backup_id
    )
