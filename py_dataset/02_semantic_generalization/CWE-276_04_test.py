import os
from pathlib import Path


def save_private_key(
    private_key: bytes,
) -> Path:
    os.umask(
        0
    )
    path = Path(
        "deployment_key.pem"
    )
    path.write_bytes(
        private_key
    )

    return path
