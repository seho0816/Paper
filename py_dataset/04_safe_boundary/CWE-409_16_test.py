import zipfile
from pathlib import Path


MAX_ENTRIES = 1000
MAX_TOTAL_SIZE = (
    100
    * 1024
    * 1024
)
MAX_ENTRY_SIZE = (
    20
    * 1024
    * 1024
)
MAX_COMPRESSION_RATIO = 100


def inspect_archive(
    archive_path: Path,
) -> list[zipfile.ZipInfo]:
    with zipfile.ZipFile(
        archive_path,
    ) as archive:
        members = archive.infolist()

        if len(
            members
        ) > MAX_ENTRIES:
            raise ValueError(
                "too many archive entries"
            )

        total_size = 0

        for member in members:
            if member.file_size > MAX_ENTRY_SIZE:
                raise ValueError(
                    "archive entry too large"
                )

            total_size += member.file_size

            if total_size > MAX_TOTAL_SIZE:
                raise ValueError(
                    "archive too large"
                )

            if (
                member.file_size > 0
                and member.compress_size == 0
            ):
                raise ValueError(
                    "invalid compressed entry"
                )

            if (
                member.compress_size > 0
                and member.file_size
                / member.compress_size
                > MAX_COMPRESSION_RATIO
            ):
                raise ValueError(
                    "compression ratio too high"
                )

        return members
