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
    # CWE-281 Fix: Improper Preservation of Permissions.
    # When restoring an external backup file, it's critical to ensure
    # the restored file has secure permissions, rather than inheriting potentially
    # insecure permissions from the original backup. This sets owner-only read/write (0o600).
    destination.chmod(0o600)
    return destination
