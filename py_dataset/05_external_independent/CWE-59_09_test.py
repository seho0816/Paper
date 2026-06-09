import tarfile
from pathlib import Path


def create_archive(
    destination: Path,
    source_directory: Path,
) -> None:
    with tarfile.open(
        destination,
        "w:gz",
    ) as archive:
        archive.add(
            source_directory,
            arcname=".",
        )
