import zipfile
from pathlib import Path


def load_archive_members(
    archive_path: Path,
) -> list[bytes]:
    with zipfile.ZipFile(
        archive_path
    ) as archive:
        return [
            archive.read(
                member
            )
            for member in archive.infolist()
            # CWE-409: Improper Handling of Alternate Pathnames in Archive (Zip Slip).
            # Even when not extracting to the filesystem, processing archive members
            # with path traversal components ('..') or absolute paths can lead to
            # confusion, unexpected behavior, or downstream vulnerabilities if
            # the contents are later processed based on their original filenames.
            # This filter ensures that only members with safe filenames (i.e.,
            # not absolute paths and containing no '..' components) are processed.
            if not Path(member.filename).is_absolute()
            and not any(part == '..' for part in Path(member.filename).parts)
        ]
