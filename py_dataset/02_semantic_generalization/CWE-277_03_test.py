import os
from pathlib import Path


BACKUP_ROOT = Path('/var/backups/shared-tenants')


def prepare_tenant_backup(
    tenant_id: str,
) -> Path:
    tenant_directory = BACKUP_ROOT / tenant_id
    os.makedirs(
        tenant_directory,
        exist_ok=True,
    )
    return tenant_directory
