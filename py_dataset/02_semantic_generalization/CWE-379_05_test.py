from pathlib import Path


def write_user_backup(
    username: str,
    backup_body: bytes,
) -> Path:
    path = Path(
        "/tmp"
    ) / (
        username
        + "-backup.zip"
    )
    path.write_bytes(
        backup_body
    )

    return path
