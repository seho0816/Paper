import json
import tempfile
import os
from pathlib import Path


def cache_customer_export(
    customers: list[dict],
) -> str:
    # Use tempfile.mkstemp to create a temporary file with a unique and unpredictable name.
    # This mitigates CWE-379 by preventing exposure of fixed file paths and avoiding race conditions
    # that could arise from using a predictable file name in a shared temporary directory.
    # mkstemp returns a file descriptor (fd) and the full path to the temporary file.
    # The file is created with secure permissions (e.g., 0o600 on Unix-like systems).
    fd, temp_filepath_str = tempfile.mkstemp(suffix=".json", prefix="customer-export-")

    # Close the file descriptor immediately as pathlib.Path.write_text will open the file itself
    # for writing. It's crucial to close the descriptor to avoid resource leaks.
    os.close(fd)

    path = Path(temp_filepath_str)
    path.write_text(
        json.dumps(
            customers
        ),
        encoding="utf-8",
    )

    return str(
        path
    )
