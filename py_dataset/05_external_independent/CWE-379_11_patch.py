import os
from pathlib import Path


class SecretExportService:
    def Create(
        self,
        request,
        context,
    ):
        path = Path(
            "/var/tmp"
        ) / "secret-export.json"

        # CWE-379 (Creation of Temporary File With Insecure Permissions) fix:
        # Create the file with secure permissions (0o600 for owner-only read/write)
        # using os.open and os.fdopen to ensure permissions are set at creation time,
        # rather than relying on default umask or changing permissions after creation.
        # os.O_WRONLY: Open for writing only.
        # os.O_CREAT: Create the file if it does not exist.
        # os.O_TRUNC: Truncate the file to zero length if it exists (mimicking Path.write_bytes behavior).
        # mode=0o600: Sets file permissions to owner read/write, no access for group/others.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode=0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(request.body)

        return {
            "path": str(
                path
            ),
        }
