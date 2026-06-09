import zipfile
from pathlib import Path, PurePosixPath

IMPORT_ROOT = Path(
    "/srv/imports",
).resolve()


def safe_extract(
    archive_path: Path,
) -> None:
    with zipfile.ZipFile(
        archive_path,
    ) as archive:
        for member in archive.infolist():
            member_path = PurePosixPath(
                member.filename,
            )

            if (
                member_path.is_absolute()
                or ".." in member_path.parts
            ):
                raise ValueError(
                    "invalid archive member path"
                )

            destination = (
                IMPORT_ROOT
                / Path(*member_path.parts)
            ).resolve()

            destination.relative_to(
                IMPORT_ROOT,
            )

            archive.extract(
                member,
                IMPORT_ROOT,
            )
