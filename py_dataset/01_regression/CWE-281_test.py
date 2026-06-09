from pathlib import Path
import shutil


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
    return destination
