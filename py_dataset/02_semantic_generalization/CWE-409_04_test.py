import tarfile
from pathlib import Path


def extract_tarball(
    archive_path: Path,
    destination: Path,
) -> None:
    with tarfile.open(
        archive_path,
        "r:gz",
    ) as archive:
        archive.extractall(
            destination
        )
