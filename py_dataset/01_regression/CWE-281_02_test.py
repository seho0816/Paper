from pathlib import Path
import shutil


IMPORT_ROOT = Path('/srv/imported-packages')


def import_uploaded_directory(
    source_directory: str,
    package_id: str,
) -> Path:
    destination = IMPORT_ROOT / package_id
    shutil.copytree(
        source_directory,
        destination,
        copy_function=shutil.copy2,
    )
    return destination
