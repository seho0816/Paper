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

            # Calculate the full intended destination path for the member
            # This combines the secure import root with the (partially validated) member path.
            destination = (
                IMPORT_ROOT
                / Path(*member_path.parts)
            ).resolve() # .resolve() canonicalizes the path, handling any '..' or symlinks

            # Crucial CWE-22 Path Traversal check:
            # Ensure the resolved destination path is strictly within the IMPORT_ROOT.
            # If it's not, it means a path traversal attempt was detected.
            try:
                # This raises a ValueError if 'destination' is not a subpath of 'IMPORT_ROOT'.
                destination.relative_to(
                    IMPORT_ROOT,
                )
            except ValueError:
                # Raise an error to prevent extraction outside the designated directory.
                raise ValueError(
                    f"path traversal detected: '{member.filename}' resolves outside '{IMPORT_ROOT}'"
                )

            # Create parent directories for the extracted member if they don't exist.
            # This ensures that the target directory structure is prepared safely.
            # If 'member' is a directory, 'destination' is the directory itself.
            # If 'member' is a file, 'destination.parent' is its parent directory.
            if member.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)

            # Instead of relying on `archive.extract`'s internal path joining,
            # which can sometimes be vulnerable to subtle path traversal bypasses,
            # manually open the archive member and write its content to the
            # already validated and resolved 'destination' path.
            # This ensures that the extracted content always lands in a safe location.
            if not member.is_dir(): # Only extract content for files, directories are already created
                with archive.open(member) as source, open(destination, "wb") as target:
                    target.write(source.read())
