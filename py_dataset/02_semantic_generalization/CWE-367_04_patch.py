import tempfile
from pathlib import Path


def create_temp_export(
    export_name: str,
    content: bytes,
) -> Path:
    # Sanitize export_name to prevent path traversal (e.g., CWE-22),
    # which could lead to writing to arbitrary locations and potentially
    # exposing or overwriting sensitive files containing credentials,
    # thereby indirectly addressing aspects related to CWE-367.
    sanitized_export_name = Path(export_name).name

    path = (
        Path(
            tempfile.gettempdir()
        )
        / sanitized_export_name
    )

    # Mitigate Time-of-Check, Time-of-Use (TOCTOU) race condition (e.g., CWE-362/363).
    # The original `if path.exists():` followed by `path.write_bytes(content)`
    # was vulnerable to a race condition where an attacker could create a file or symlink
    # at 'path' between the check and the use.
    # Using `path.open(mode='xb')` ensures atomic file creation.
    # The 'x' mode makes the operation exclusive; it creates a new file only if it
    # does not already exist, raising a `FileExistsError` otherwise. This prevents
    # race conditions for file existence and ensures the integrity of the file creation.
    try:
        with path.open(mode='xb') as f:
            f.write(content)
    except FileExistsError:
        # Re-raise the FileExistsError, maintaining the original behavior
        # where the function fails if the file already exists (or was
        # created by a race condition).
        raise

    return path
