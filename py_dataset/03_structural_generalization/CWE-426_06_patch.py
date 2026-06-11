import subprocess
import shutil
from dataclasses import dataclass


@dataclass(frozen=True)
class ArchiveRequest:
    source: str
    destination: str


class ArchiveService:
    # Resolve the absolute path of the 'tar' executable once
    _TAR_COMMAND_PATH = shutil.which("tar")

    def __init__(self):
        if self._TAR_COMMAND_PATH is None:
            raise RuntimeError("The 'tar' command was not found on the system path. "
                               "Please ensure it is installed and accessible.")

    def create(
        self,
        request: ArchiveRequest,
    ) -> None:
        subprocess.run(
            [
                self._TAR_COMMAND_PATH,  # Use the absolute path to prevent untrusted search path vulnerability (CWE-426)
                "czf",
                request.destination,
                request.source,
            ],
            check=True,
        )
