import os
from pathlib import Path


def save_export(
    content: bytes,
) -> Path:
    path = Path(
        f"/tmp/export-{os.getpid()}.csv"
    )
    path.write_bytes(
        content
    )

    return path
