import os
import tempfile
from pathlib import Path


def save_preview(
    content: bytes,
) -> Path:
    fd, path_str = tempfile.mkstemp(suffix=".bin")
    with os.fdopen(fd, 'wb') as tmp_file:
        tmp_file.write(content)

    return Path(path_str)
