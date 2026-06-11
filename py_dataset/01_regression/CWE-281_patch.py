from pathlib import Path
import shutil
import os


PUBLISH_ROOT = Path('/var/app/published')


def publish_uploaded_file(
    upload_path: str,
) -> Path:
    source = Path(upload_path)
    destination = PUBLISH_ROOT / source.name
    shutil.copy2(
        source,
        destination,
    )
    # CWE-281: Improper Preservation of Permissions
    # shutil.copy2 copies file metadata, including permissions, from the source.
    # If the source file had insecure permissions (e.g., world-writable),
    # these would be copied to the published file.
    # Explicitly set secure permissions (e.g., 0o644 for files)
    # to prevent unauthorized access or modification.
    os.chmod(destination, 0o644)
    return destination
