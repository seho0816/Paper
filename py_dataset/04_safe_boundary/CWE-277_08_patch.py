import os
from pathlib import Path


SHARED_ROOT = Path('/srv/shared')
PRIVATE_EXPORTS = SHARED_ROOT / 'private-exports'


def create_private_export_directory() -> Path:
    os.makedirs(
        PRIVATE_EXPORTS,
        mode=0o700,
        exist_ok=True,
    )
    os.chmod(
        PRIVATE_EXPORTS,
        0o700,
    )
    actual_mode = (
        os.stat(
            PRIVATE_EXPORTS
        ).st_mode
        & 0o777
    )
    if actual_mode != 0o700:
        raise PermissionError(
            'insecure export directory mode'
        )
    return PRIVATE_EXPORTS

