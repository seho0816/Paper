import shutil
from pathlib import Path


def publish_report(
    source: Path,
    destination: Path,
) -> None:
    shutil.copyfile(
        source,
        destination,
    )
