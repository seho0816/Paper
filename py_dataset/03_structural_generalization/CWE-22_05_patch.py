import shutil
import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArchiveImport:
    archive_path: Path
    destination: Path


class ArchiveReader:
    def members(
        self,
        archive_path: Path,
    ) -> list[zipfile.ZipInfo]:
        with zipfile.ZipFile(
            archive_path,
        ) as archive:
            return archive.infolist()


class ArchiveImporter:
    def __init__(
        self,
        reader: ArchiveReader,
    ) -> None:
        self._reader = reader

    def import_archive(
        self,
        request: ArchiveImport,
    ) -> None:
        members = self._reader.members(
            request.archive_path,
        )

        # Ensure the destination directory exists and is resolved to its canonical path.
        # This provides a stable, absolute base for path traversal checks.
        request.destination.mkdir(parents=True, exist_ok=True)
        resolved_destination = request.destination.resolve()

        with zipfile.ZipFile(
            request.archive_path,
        ) as archive:
            for member in members:
                # Construct the potential full path for the extracted member within the destination.
                potential_target_path = request.destination / member.filename

                # Resolve the potential target path to its canonical form.
                # `strict=False` allows resolution even if the file or some intermediate
                # directories do not exist yet, which is expected during extraction.
                resolved_potential_target_path = potential_target_path.resolve(strict=False)

                # CWE-22 Path Traversal Fix:
                # Check if the resolved potential target path is a subpath of the resolved destination.
                # If `resolved_potential_target_path` is not relative to `resolved_destination`,
                # it indicates a path traversal attempt (e.g., using `../` or absolute paths
                # in `member.filename` to escape the intended extraction directory).
                if not resolved_potential_target_path.is_relative_to(resolved_destination):
                    # Path traversal attempt detected. Skip this member to prevent
                    # writing files outside the authorized directory.
                    continue

                # If the member is a directory entry, ensure the directory itself is created
                # and skip the file content copying part.
                if member.is_dir():
                    potential_target_path.mkdir(parents=True, exist_ok=True)
                    continue

                # If validation passes and it's a file, set the actual target path to the potential path.
                target = potential_target_path

                # Create parent directories for the target file. This is safe now
                # because the 'target' path has been validated against path traversal.
                target.parent.mkdir(
                    parents=True,
                    exist_ok=True,
                )

                with archive.open(member) as source:
                    with target.open("wb") as destination:
                        shutil.copyfileobj(
                            source,
                            destination,
                        )
