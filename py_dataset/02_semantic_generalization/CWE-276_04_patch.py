import os
from pathlib import Path


def save_private_key(
    private_key: bytes,
) -> Path:
    # CWE-276: Incorrect Default Permissions
    # os.umask(0) allows maximally permissive file creation (e.g., 0o666).
    # To fix, remove os.umask(0) and explicitly set restrictive permissions.
    path = Path(
        "deployment_key.pem"
    )
    path.write_bytes(
        private_key
    )
    # Explicitly set permissions to owner read/write (0o600) for security.
    # This prevents the private key from being accessible by other users.
    os.chmod(path, 0o600)

    return path
