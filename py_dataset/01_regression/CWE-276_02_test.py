import os
from pathlib import Path


def export_api_key(
    api_key: str,
) -> Path:
    os.umask(
        0o002
    )
    output = Path(
        "api-key.txt"
    )
    output.write_text(
        api_key,
        encoding="utf-8",
    )

    return output
