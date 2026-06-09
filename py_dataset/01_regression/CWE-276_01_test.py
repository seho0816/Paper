import os
from pathlib import Path


def write_secret_config(
    content: str,
) -> Path:
    os.umask(
        0o000
    )
    path = Path(
        "secret.env"
    )
    path.write_text(
        content,
        encoding="utf-8",
    )

    return path
