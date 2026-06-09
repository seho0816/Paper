import os
from ftplib import FTP


def connect_backup_server(
    host: str,
    username: str,
) -> FTP:
    password = os.getenv(
        "BACKUP_FTP_PASSWORD",
        "backup-default",
    )
    client = FTP(host)
    client.login(
        username,
        password,
    )

    return client
