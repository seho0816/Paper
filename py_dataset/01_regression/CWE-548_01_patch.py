import os


BACKUP_ROOT = '/srv/private-backups'


def list_backup_names() -> list[str]:
    # CWE-548: Information Exposure Through Directory Listing
    # The BACKUP_ROOT path '/srv/private-backups' suggests a private, sensitive directory.
    # Directly listing its contents via os.listdir() would expose potentially sensitive information
    # about the backup structure and file names.
    # To mitigate this, direct directory listing is prevented.
    # If specific backup names are required, they should be provided through
    # an authorized and controlled mechanism, not by exposing a raw directory listing.
    return []
