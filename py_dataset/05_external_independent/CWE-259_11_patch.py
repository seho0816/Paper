import os
from ftplib import FTP


def connect_backup_server(
    host: str,
    username: str,
) -> FTP:
    # CWE-259: Use of Hard-coded Password vulnerability fixed.
    # The hard-coded default value for the password has been removed.
    # Now, if the 'BACKUP_FTP_PASSWORD' environment variable is not set,
    # an environment error (KeyError) will be raised, enforcing that
    # the password must be explicitly provided through secure configuration.
    password = os.environ["BACKUP_FTP_PASSWORD"]
    client = FTP(host)
    client.login(
        username,
        password,
    )

    return client
