from ftplib import FTP


def list_backup_files(
    host: str,
    username: str,
    password: str,
) -> list[str]:
    client = None
    try:
        client = FTP(
            host
        )
        client.login(
            username,
            password,
        )

        return client.nlst()
    finally:
        if client:
            client.quit()
