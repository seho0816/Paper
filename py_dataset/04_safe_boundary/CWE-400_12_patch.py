import zipfile
from pathlib import Path


MAX_ENTRIES = 1000
MAX_TOTAL_SIZE = 100 * 1024 * 1024


def inspect_archive(
    archive_path: Path,
) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(
        archive_path,
    ) as archive:
        members = archive.infolist()

        if len(members) > MAX_ENTRIES:
            raise ValueError(
                "too many archive entries"
            )

        total_size = sum(
            member.file_size
            for member in members
        )

        if total_size > MAX_TOTAL_SIZE:
            raise ValueError(
                "archive too large"
            )

        return members

