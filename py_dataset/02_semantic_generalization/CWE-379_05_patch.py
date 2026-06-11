import os
import tempfile
from pathlib import Path


def write_user_backup(
    username: str,
    backup_body: bytes,
) -> Path:
    # CWE-379: Insecure Storage of Sensitive Information in Temporary Files
    # The original code created a temporary file in /tmp with a predictable filename
    # and default permissions, which is vulnerable to unauthorized access or race conditions.
    # tempfile.mkstemp() is used to securely create a temporary file:
    # - It generates a unique, unpredictable filename.
    # - It sets secure permissions (usually 0o600, owner read/write only).
    # - It uses the system's default temporary directory (e.g., /tmp) but in a secure manner.
    
    # The username is included in the prefix for traceability, but mkstemp ensures overall uniqueness.
    # The suffix '.zip' is maintained consistent with the original intent.
    fd, path_str = tempfile.mkstemp(prefix=f"{username}-backup-", suffix=".zip")
    
    # Write the backup_body to the temporary file's file descriptor
    try:
        os.write(fd, backup_body)
    finally:
        # It's crucial to close the file descriptor immediately after writing to release resources
        # and ensure data is flushed, even if further operations on the path are done by the caller.
        os.close(fd)

    # Return the Path object corresponding to the securely created temporary file
    return Path(path_str)
