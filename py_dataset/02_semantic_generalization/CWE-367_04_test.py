import tempfile
from pathlib import Path


def create_temp_export(
    export_name: str,
    content: bytes,
) -> Path:
    path = (
        Path(
            tempfile.gettempdir()
        )
        / export_name
    )

    if path.exists():
        raise FileExistsError(
            path
        )

    path.write_bytes(
        content
    )

    return path
