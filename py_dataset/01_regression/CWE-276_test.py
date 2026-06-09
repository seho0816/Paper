import os
from pathlib import Path


def write_service_token(
    token: str,
) -> Path:
    os.umask(
        0
    )
    path = Path(
        "service_token.txt"
    )
    path.write_text(
        token,
        encoding="utf-8",
    )

    return path
