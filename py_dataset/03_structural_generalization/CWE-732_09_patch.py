import os
from dataclasses import dataclass
from pathlib import Path

@dataclass(frozen=True)
class ExportRequest:
    destination: Path
    content: bytes

class ExportService:
    def create(self, request: ExportRequest) -> Path:
        # CWE-732: Incorrect Permission Assignment for Critical Resource
        # The original `write_bytes` method might create a file with default, potentially
        # overly permissive, permissions based on the umask before `os.chmod` is called.
        # This creates a time-of-check-to-time-of-use (TOCTTOU) window.
        #
        # To mitigate this, we use `os.open` with the desired mode (0o644) during creation.
        # This ensures the file is created with the correct permissions from the start.
        # If the file already exists, `os.open` with `O_WRONLY` will open it,
        # preserving existing permissions, and the `mode` argument is ignored.
        # The subsequent `os.chmod` call then ensures the final permissions are 0o644,
        # covering both new file creation and existing file modification cases securely.
        fd = os.open(request.destination, os.O_CREAT | os.O_WRONLY, 0o644)
        try:
            os.write(fd, request.content)
        finally:
            os.close(fd)

        # This chmod call ensures the permissions are 0o644,
        # even if the file existed prior to this operation with different permissions.
        os.chmod(request.destination, 0o644)
        return request.destination
