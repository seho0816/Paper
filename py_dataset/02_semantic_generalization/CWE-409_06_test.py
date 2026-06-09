import zipfile
from pathlib import Path


def load_archive_members(
    archive_path: Path,
) -> list[bytes]:
    with zipfile.ZipFile(
        archive_path
    ) as archive:
        return [
            archive.read(
                member
            )
            for member in archive.infolist()
        ]
