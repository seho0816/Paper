import tarfile
from pathlib import Path


MAX_FILES = 500
MAX_TOTAL_SIZE = 50 * 1024 * 1024


def extract_tarball(
    archive_path: Path,
    destination: Path,
) -> None:
    with tarfile.open(
        archive_path,
        "r:*",
    ) as archive:
        members = archive.getmembers()

        if len(members) > MAX_FILES:
            raise ValueError(
                "too many files"
            )

        total_size = sum(
            member.size
            for member in members
            if member.isfile()
        )

        if total_size > MAX_TOTAL_SIZE:
            raise ValueError(
                "archive too large"
            )

        for member in members:
            archive.extract(
                member,
                destination,
            )
