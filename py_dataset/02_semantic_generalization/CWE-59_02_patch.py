import shutil
from pathlib import Path


def publish_report(
    source: Path,
    destination: Path,
) -> None:
    shutil.copyfile(
        source,
        destination,
        follow_symlinks=False,  # CWE-59: Prevent following symbolic links in the destination path
    )
