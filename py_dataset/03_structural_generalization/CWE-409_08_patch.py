import zipfile
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ArchiveRequest:
    archive_path: Path
    destination: Path


class ArchiveService:
    def extract(
        self,
        request: ArchiveRequest,
    ) -> list[Path]:
        # Ensure the destination directory exists.
        request.destination.mkdir(parents=True, exist_ok=True)
        # Resolve the destination path to get its canonical form.
        # This is crucial for robust security checks against directory traversal.
        resolved_destination = request.destination.resolve()

        with zipfile.ZipFile(
            request.archive_path
        ) as archive:
            for member in archive.infolist():
                # Construct the full path where this member *would* be extracted.
                # Use request.destination as the base to correctly handle internal paths
                # like "dir/file.txt" within the destination.
                target_path = request.destination / member.filename

                # Resolve the target path to canonicalize it. This step
                # resolves any '..' components and symlinks to determine the final,
                # absolute path where the file would be placed.
                resolved_target_path = target_path.resolve()

                # CRITICAL SECURITY CHECK (CWE-409 - Zip Slip):
                # Ensure that the resolved target path is strictly a sub-path
                # of the resolved destination path. If it's not, it indicates
                # an attempted directory traversal (Zip Slip) attack.
                if not resolved_target_path.is_relative_to(resolved_destination):
                    # A malicious entry attempting to write outside the
                    # intended destination directory has been detected.
                    # Raising an error is the most secure response to prevent
                    # unintended file system modifications.
                    raise ValueError(
                        f"Attempted path traversal detected: archive member '{member.filename}' "
                        f"resolves to '{resolved_target_path}', which is outside "
                        f"the designated destination '{resolved_destination}'."
                    )

                if member.is_dir():
                    # If the member is a directory, create it.
                    resolved_target_path.mkdir(parents=True, exist_ok=True)
                else:
                    # If the member is a file, ensure its parent directories exist
                    # and then write the file content.
                    resolved_target_path.parent.mkdir(parents=True, exist_ok=True)
                    with archive.open(member) as source, open(resolved_target_path, "wb") as target:
                        target.write(source.read())

        # The original code returns all files and directories found in the
        # destination after extraction. This behavior is maintained.
        return list(
            request.destination.rglob(
                "*"
            )
        )
