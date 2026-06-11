import os
import tempfile
from pathlib import Path


class ResetExportService:
    def create(
        self,
        content: str,
    ) -> Path:
        # CWE-379: Creation of Temporary File With Insecure Permissions
        # Original code used a fixed path, making it vulnerable to race conditions
        # (e.g., symlink attacks) or unauthorized access due to predictable name
        # and default permissions.

        # Fix: Use tempfile.mkstemp to securely create a unique temporary file.
        # mkstemp ensures unique filenames and secure permissions (0o600 by default),
        # mitigating race conditions and unauthorized access.
        # It returns a file descriptor (fd) and the path string.
        fd, path_str = tempfile.mkstemp(suffix=".csv")

        try:
            # Open the file using the file descriptor in text write mode with UTF-8 encoding.
            # os.fdopen ensures the file is closed automatically by the 'with' statement.
            with os.fdopen(fd, 'w', encoding="utf-8") as temp_file:
                temp_file.write(content)

            # Convert the path string to a Path object and return it.
            # The caller is now responsible for handling this temporary file,
            # including its eventual deletion if it's no longer needed.
            return Path(path_str)
        except Exception:
            # If an error occurs during writing, ensure the created temporary file is removed
            # to prevent orphaned files.
            os.remove(path_str)
            raise
