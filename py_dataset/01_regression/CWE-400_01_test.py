import zipfile
from pathlib import Path


def extract_archive(
    archive_path: Path,
    destination: Path,
) -> None:
    with zipfile.ZipFile(
        archive_path,
    ) as archive:
        archive.extractall(
            destination,
        )
