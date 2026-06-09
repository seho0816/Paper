import os
from pathlib import Path


BACKUP_ROOT = Path('/var/backups/shared-tenants')


def prepare_tenant_backup(
    tenant_id: str,
) -> Path:
    tenant_directory = BACKUP_ROOT / tenant_id
    os.makedirs(
        tenant_directory,
        mode=0o700,  # CWE-277: Explicitly set secure permissions to prevent unauthorized access
        exist_ok=True,
    )
    return tenant_directory
