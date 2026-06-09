import os


BACKUP_ROOT = '/srv/private-backups'


def list_backup_names() -> list[str]:
    return os.listdir(
        BACKUP_ROOT
    )
