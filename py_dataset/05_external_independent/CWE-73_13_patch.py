import zipfile
from pathlib import Path


def create_bundle(
    source_files: list[Path],
    output_path: str,
) -> Path:
    # CWE-73: External Control of File Name or Path
    # The vulnerability lies in using `output_path` directly to construct the `destination` Path object,
    # which could allow an attacker to specify an arbitrary file path (e.g., using '..' for directory traversal
    # or absolute paths) to write the zip file outside the intended directory.

    # Mitigation:
    # 1. Define a safe base directory (e.g., the current working directory).
    # 2. Validate the `output_path` to ensure it does not attempt to escape this base directory.
    #    - If `output_path` is an absolute path or contains directory traversal sequences ('..'),
    #      sanitize it by forcing it to be a filename within the safe base directory.
    #    - Otherwise, combine it with the safe base directory and resolve it, then perform a final check.

    destination_path_obj = Path(output_path)

    # Define the intended safe root directory for file creation (e.g., current working directory).
    # Resolve it to get its absolute, canonical form, handling any symlinks in the CWD path itself.
    safe_root = Path.cwd().resolve()

    # Determine the final destination path
    final_destination: Path

    # Check if the path attempts to be absolute or contains directory traversal sequences ('..').
    # `destination_path_obj.is_absolute()` checks for paths like `/etc/passwd.zip`.
    # `any(p == '..' for p in destination_path_obj.parts)` checks for paths like `../../tmp/file.zip`.
    if destination_path_obj.is_absolute() or any(p == '..' for p in destination_path_obj.parts):
        # If the path is absolute or attempts directory traversal,
        # sanitize it by forcing it to be created directly within the `safe_root`
        # using only the filename part of the user's input.
        final_destination = safe_root / destination_path_obj.name
    else:
        # If the path is relative and does not contain '..',
        # join it with the `safe_root` and resolve to get the canonical path.
        # This handles paths like `subdir/file.zip` correctly.
        candidate_destination = (safe_root / destination_path_obj).resolve()

        # Perform a final check to ensure the resolved path is indeed a child of, or is, the `safe_root`.
        # This catches any edge cases or complex symlink scenarios that might still cause escape.
        if not candidate_destination.is_relative_to(safe_root):
            # If it somehow still escapes, fall back to the safest option:
            # create the file directly in the `safe_root` with the provided filename.
            final_destination = safe_root / destination_path_obj.name
        else:
            final_destination = candidate_destination

    destination = final_destination

    with zipfile.ZipFile(
        destination,
        "w",
    ) as archive:
        for source in source_files:
            archive.write(
                source,
                arcname=source.name,
            )

    return destination
