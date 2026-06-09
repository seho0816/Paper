from pathlib import Path
import shutil


def restore_external_backup_file(
    backup_file: str,
    restore_root: Path,
) -> Path:
    source = Path(backup_file)
    destination = restore_root / source.name
    shutil.copy2(
        source,
        destination,
    )
    return destination
