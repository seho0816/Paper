import zipfile
from pathlib import Path


EXTRACT_ROOT = Path(
    "/tmp/extracted"
)


def extract_uploaded_archive(
    archive_path: Path,
) -> None:
    with zipfile.ZipFile(
        archive_path
    ) as archive:
        archive.extractall(
            EXTRACT_ROOT
        )
