import os
from pathlib import Path


def write_secret_config(
    content: str,
) -> Path:
    # CWE-276 fix: Removed os.umask(0o000) which would set highly permissive
    # default permissions for newly created files, making them world-readable/writable.
    # Instead, the file permissions are explicitly set after creation to ensure security.
    path = Path(
        "secret.env"
    )
    path.write_text(
        content,
        encoding="utf-8",
    )
    # CWE-276 fix: Explicitly set file permissions to 0o600 (read/write for owner only).
    # This ensures that the 'secret.env' file is not accessible by other users or groups.
    os.chmod(path, 0o600)

    return path
