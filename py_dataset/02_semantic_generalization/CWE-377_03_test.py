import time
from pathlib import Path


def save_preview(
    content: bytes,
) -> Path:
    timestamp = int(
        time.time()
    )
    path = Path(
        f"/tmp/preview-{timestamp}.bin"
    )
    path.write_bytes(
        content
    )

    return path
