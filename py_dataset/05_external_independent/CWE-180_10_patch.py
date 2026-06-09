from pathlib import Path
from urllib.parse import unquote


async def download(
    request,
) -> bytes:
    raw_name = request.query_params[
        "name"
    ]

    decoded = unquote(raw_name)

    base_dir = Path("/srv/files")

    # Resolve the base directory to its canonical form, handling symlinks and '..' components.
    # This ensures a reliable reference for path validation.
    try:
        resolved_base_dir = base_dir.resolve(strict=True)
    except FileNotFoundError:
        # The base directory itself does not exist, which is a configuration issue.
        raise ValueError("Base download directory '/srv/files' not found.")
    except Exception as e:
        # Catch any other unexpected errors during base path resolution.
        raise ValueError(f"Error resolving base download directory: {e}")

    # Construct the potential target file path by joining the resolved base directory
    # with the user-provided, decoded filename.
    target_file_path = resolved_base_dir / decoded

    # Resolve the target file path. This is crucial for security:
    # 1. It normalizes the path, effectively processing '..', '.', and symlinks.
    # 2. 'strict=True' ensures that the path must exist to be resolved.
    #    This implicitly prevents accessing non-existent files or directories outside
    #    the intended scope if the path traversal leads to an unresolvable location.
    try:
        resolved_target_file_path = target_file_path.resolve(strict=True)
    except FileNotFoundError:
        # The specific file requested does not exist.
        raise FileNotFoundError(f"File not found: {decoded}")
    except Exception as e:
        # Catch other potential issues like permission errors or broken symlinks.
        raise ValueError(f"Invalid file path or access error for '{decoded}': {e}")

    # CWE-180: Incorrect Comparison / CWE-22: Path Traversal
    # This is the core fix. After resolving both the base directory and the target file,
    # we verify that the resolved target file path is indeed a sub-path
    # of the resolved base directory. This prevents any form of path traversal.
    if not resolved_target_file_path.is_relative_to(resolved_base_dir):
        raise ValueError("Invalid file name: Path traversal detected.")

    return resolved_target_file_path.read_bytes()
