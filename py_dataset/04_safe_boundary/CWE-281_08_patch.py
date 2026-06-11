from pathlib import Path
import os
import shutil


PUBLISH_ROOT = Path('/var/app/published')


def publish_uploaded_file(
    upload_path: str,
) -> Path:
    source = Path(upload_path)
    destination = PUBLISH_ROOT / source.name
    shutil.copyfile(
        source,
        destination,
    )
    os.chmod(
        destination,
        0o640,
    )
    return destination

