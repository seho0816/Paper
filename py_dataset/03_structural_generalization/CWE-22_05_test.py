import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArchiveImport:
    archive_path: Path
    destination: Path


class ArchiveReader:
    def members(
        self,
        archive_path: Path,
    ) -> list[zipfile.ZipInfo]:
        with zipfile.ZipFile(
            archive_path,
        ) as archive:
            return archive.infolist()


class ArchiveImporter:
    def __init__(
        self,
        reader: ArchiveReader,
    ) -> None:
        self._reader = reader

    def import_archive(
        self,
        request: ArchiveImport,
    ) -> None:
        members = self._reader.members(
            request.archive_path,
        )

        with zipfile.ZipFile(
            request.archive_path,
        ) as archive:
            for member in members:
                target = (
                    request.destination
                    / member.filename
                )

                target.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                with archive.open(member) as source:
                    with target.open("wb") as destination:
                        shutil.copyfileobj(
                            source,
                            destination,
                        )
