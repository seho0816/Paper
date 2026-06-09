import shutil
import stat
import zipfile
from pathlib import Path


def extract_archive(
    archive_path: Path,
    destination: Path,
) -> None:
    destination_root = destination.resolve()

    with zipfile.ZipFile(
        archive_path,
    ) as archive:
        for member in archive.infolist():
            mode = member.external_attr >> 16

            if stat.S_ISLNK(
                mode
            ):
                raise ValueError(
                    "symbolic links are not allowed"
                )

            # Construct the full path and resolve it to its canonical form
            target = (
                destination_root
                / member.filename
            ).resolve()

            # CWE-409: Ensure the resolved path does not escape the destination directory.
            # This explicitly prevents path traversal (Zip Slip) and writing to absolute paths outside the destination.
            if not target.is_relative_to(destination_root):
                raise ValueError(
                    f"Path traversal detected: '{member.filename}' attempts to write outside '{destination_root}'"
                )

            if member.is_dir():
                target.mkdir(
                    parents=True,
                    exist_ok=True,
                )
                continue

            target.parent.mkdir(
                parents=True,
                exist_ok=True,
            )

            with archive.open(
                member,
            ) as source:
                with target.open(
                    "wb"
                ) as output:
                    shutil.copyfileobj(
                        source,
                        output,
                    )
