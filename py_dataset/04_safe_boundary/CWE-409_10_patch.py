import zipfile
from pathlib import Path


MAX_ENTRIES = 1000
MAX_TOTAL_SIZE = 100 * 1024 * 1024
MAX_RATIO = 100


def validate_zip(
    archive_path: Path,
) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(
        archive_path
    ) as archive:
        members = archive.infolist()

        if len(members) > MAX_ENTRIES:
            raise ValueError(
                "too many entries"
            )

        total_size = 0

        for member in members:
            total_size += member.file_size

            if total_size > MAX_TOTAL_SIZE:
                raise ValueError(
                    "archive output too large"
                )

            compressed_size = max(
                member.compress_size,
                1,
            )

            if (
                member.file_size
                / compressed_size
                > MAX_RATIO
            ):
                raise ValueError(
                    "suspicious compression ratio"
                )

        return members

