import tarfile
from pathlib import Path


def archive_project(
    project_root: Path,
    archive_destination: str,
) -> Path:
    # CWE-73: External Control of File Name or Path
    # The 'archive_destination' parameter directly controls the output file path.
    # An attacker could provide a path like "../../../etc/passwd" or "/tmp/malicious.tar.gz"
    # to write the archive to an arbitrary location on the file system,
    # potentially overwriting critical files or placing malicious content.

    # Fix: Validate and sanitize the archive_destination to ensure it is confined
    # to an allowed base directory and does not contain path traversal sequences
    # or absolute paths.

    # 1. Convert the user-supplied string to a Path object.
    output_candidate = Path(archive_destination)

    # 2. Prevent absolute paths. If the destination is absolute, it bypasses
    # any confinement to a base directory. Rejecting such input is a secure practice.
    if output_candidate.is_absolute():
        raise ValueError("Archive destination cannot be an absolute path.")

    # 3. Define the base directory for confinement. Without a specific base directory
    # provided in the function signature, the current working directory is the
    # most reasonable implicit base to ensure local confinement.
    base_dir = Path.cwd()

    # 4. Construct the full intended path by joining the base directory with the
    # (now guaranteed relative) output candidate path.
    potential_output_path = base_dir / output_candidate

    # 5. Resolve the path to its canonical form. This normalizes '..' components
    # and resolves any symbolic links. This is crucial for detecting path traversal.
    resolved_output = potential_output_path.resolve()

    # 6. Verify that the resolved path is still contained within the base directory.
    # If `relative_to()` raises a ValueError, it means the path attempts to escape
    # the base directory (e.g., through path traversal like "../../").
    try:
        resolved_output.relative_to(base_dir)
    except ValueError:
        raise ValueError("Archive destination path attempts to escape the base directory.")

    # The validated and confined path is now used for archive creation.
    output = resolved_output

    with tarfile.open(
        output,
        "w:gz",
    ) as archive:
        archive.add(
            project_root,
            arcname=".",
        )

    return output
