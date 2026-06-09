import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ArchiveLookup:
    archive_path: str
    member_name: str


class ArchiveCommandRunner:
    def list_member(
        self,
        request: ArchiveLookup,
    ) -> str:
        completed = subprocess.run(
            [
                "tar",
                "tf",
                "--",  # Treat subsequent arguments as non-options (filenames/members)
                request.archive_path,
                request.member_name,
            ],
            capture_output=True,
            text=True,
            check=False,
        )

        return completed.stdout
