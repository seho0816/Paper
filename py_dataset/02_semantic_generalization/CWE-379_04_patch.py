import json
import tempfile
import os
from pathlib import Path


def dump_refresh_tokens(
    tokens: list[dict],
) -> Path:
    # CWE-379: Creation of Temporary File With Insecure Permissions.
    # The original code created a file in /var/tmp with default permissions,
    # which could expose sensitive data to other users or allow tampering.
    # To fix this, we use tempfile.mkstemp, which creates a unique temporary file
    # with secure permissions (0o600 by default), preventing unauthorized access.
    # We specify the directory as "/var/tmp" to maintain the original intent for location.
    fd, path_str = tempfile.mkstemp(suffix=".json", dir="/var/tmp")

    # Open the file descriptor obtained from mkstemp for writing.
    # The 'with' statement ensures the file descriptor is properly closed.
    with os.fdopen(fd, 'w', encoding="utf-8") as temp_file:
        temp_file.write(json.dumps(tokens))

    # Convert the path string returned by mkstemp to a Path object,
    # maintaining the function's return type signature.
    return Path(path_str)
