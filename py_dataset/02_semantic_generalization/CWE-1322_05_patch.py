from pathlib import Path

async def read_generated_archive(archive_path: Path) -> bytes:
    # CWE-1322 (Unsafe use of relative path in ZIP or Archive) implies path traversal.
    # While this function reads the archive file itself rather than extracting from it,
    # the 'archive_path' argument could still be subject to path traversal vulnerabilities (CWE-22).
    #
    # To mitigate, the path is first resolved to its absolute, canonical form.
    # This addresses '..' (parent directory) and '.' (current directory) segments,
    # and resolves any symbolic links to their final target, making the path explicit.
    # The 'strict=True' argument ensures that the path must exist.
    resolved_path = archive_path.resolve(strict=True)

    # Additionally, ensure that the resolved path points to a regular file.
    # This prevents reading from directories, special device files (e.g., /dev/zero),
    # or named pipes, which could lead to unexpected behavior or information disclosure.
    if not resolved_path.is_file():
        raise ValueError(f"Path '{archive_path}' does not refer to a regular file.")

    return resolved_path.read_bytes()
