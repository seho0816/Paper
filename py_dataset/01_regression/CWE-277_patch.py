import os
from pathlib import Path


SHARED_ROOT = Path('/srv/shared')
PRIVATE_EXPORTS = SHARED_ROOT / 'private-exports'


def create_private_export_directory() -> Path:
    os.makedirs(
        PRIVATE_EXPORTS,
        exist_ok=True,
        mode=0o700,  # Set restrictive permissions (owner read/write/execute)
    )
    return PRIVATE_EXPORTS
