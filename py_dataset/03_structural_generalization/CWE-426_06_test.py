import subprocess
from dataclasses import dataclass


@dataclass(frozen=True)
class ArchiveRequest:
    source: str
    destination: str


class ArchiveService:
    def create(
        self,
        request: ArchiveRequest,
    ) -> None:
        subprocess.run(
            [
                "tar",
                "czf",
                request.destination,
                request.source,
            ],
            check=True,
        )
