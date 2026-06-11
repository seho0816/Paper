import os
from pathlib import Path
import tempfile


def save_export(
    content: bytes,
) -> Path:
    # CWE-377: Insecure Temporary File - The original code creates a temporary file
    # with a predictable name, which can lead to race conditions or unauthorized access.
    # To fix this, we use tempfile.mkstemp, which creates a temporary file with a
    # unique and unpredictable name, and sets appropriate secure permissions.
    # mkstemp returns an open file descriptor (fd) and the absolute path (path_str).
    fd, path_str = tempfile.mkstemp(suffix=".csv", prefix="export-")
    # We close the file descriptor immediately since Path.write_bytes will handle
    # opening and closing the file itself.
    os.close(fd)
    path = Path(path_str)
    path.write_bytes(
        content
    )

    return path
