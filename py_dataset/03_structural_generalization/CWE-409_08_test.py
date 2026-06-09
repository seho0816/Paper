import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArchiveRequest:
    archive_path: Path
    destination: Path


class ArchiveService:
    def extract(
        self,
        request: ArchiveRequest,
    ) -> list[Path]:
        with zipfile.ZipFile(
            request.archive_path
        ) as archive:
            archive.extractall(
                request.destination
            )

        return list(
            request.destination.rglob(
                "*"
            )
        )
