import tempfile
from pathlib import Path
import os


def write_password_reset_export(
    content: str,
) -> str:
    # CWE-379: Signature Not Verified (often related to insecure temporary file creation).
    # The original code created a temporary file with a fixed and predictable name
    # in a common, potentially shared directory (/tmp). This makes the file vulnerable
    # to various attacks, such as symbolic link attacks, race conditions (TOCTOU),
    # or information disclosure, as another process could interfere with the file.
    #
    # To mitigate this, tempfile.mkstemp is used. It securely creates a unique
    # temporary file with restrictive permissions (e.g., 0o600 by default),
    # preventing other users or processes from easily accessing or replacing it.
    # It returns a low-level file descriptor (fd) and the unique path to the file.
    fd, output_path_str = tempfile.mkstemp(
        suffix=".csv",
        dir="/tmp"
    )

    # The file descriptor returned by mkstemp needs to be closed.
    # We close it here because we will use pathlib's write_text method
    # which will open and close the file itself.
    os.close(fd)

    # Convert the string path obtained from mkstemp to a Path object
    # to maintain consistency with the original code's usage of pathlib.
    output_path = Path(output_path_str)

    # Write the provided content to the securely created temporary file.
    output_path.write_text(
        content,
        encoding="utf-8",
    )

    # Return the string representation of the path to the created file.
    return str(
        output_path
    )
