from pathlib import Path
import tarfile
import os

def archive_logs(log_directory: str) -> str:
    # --- CWE-552 Fix for input 'log_directory' (Information Exposure via Path Traversal) ---
    # Define a safe base directory where legitimate logs are expected to reside.
    # This path should be securely configured (e.g., via an environment variable).
    # If the environment variable is not set, a sensible default like a 'logs' subdirectory
    # in the current working directory is used, ensuring the application operates within a defined scope.
    safe_log_root_str = os.environ.get("APP_LOG_ROOT", str(Path.cwd() / "logs"))
    safe_log_root = Path(safe_log_root_str).resolve()
    safe_log_root.mkdir(parents=True, exist_ok=True) # Ensure the safe root directory exists

    # Convert the input `log_directory` string to a Path object for secure path manipulation.
    input_log_path = Path(log_directory)

    # Resolve the input path relative to the `safe_log_root`.
    # This step is critical for preventing directory traversal.
    # If `input_log_path` is an absolute path (e.g., "/etc/passwd"), then `safe_log_root / input_log_path`
    # will result directly in `input_log_path` (e.g., Path("/etc/passwd")).
    # If `input_log_path` is a relative path (e.g., "../../../sensitive"), it will be combined with
    # `safe_log_root` (e.g., Path("/app/logs/../../../sensitive")).
    # `.resolve(strict=False)` canonicalizes the path, handling '..' components and symlinks.
    # `strict=False` is used to allow resolution even if the target `log_directory` (e.e.g, a new log subdirectory)
    # does not exist yet.
    potential_resolved_path = (safe_log_root / input_log_path).resolve(strict=False)

    # Validate if the `potential_resolved_path` is indeed within the `safe_log_root` or is `safe_log_root` itself.
    log_directory_to_archive = None
    try:
        # `Path.relative_to()` raises a `ValueError` if `potential_resolved_path` is not a subpath
        # of `safe_log_root` (e.g., if path traversal or an arbitrary absolute path outside the root was attempted).
        potential_resolved_path.relative_to(safe_log_root)
        log_directory_to_archive = potential_resolved_path
    except ValueError:
        # If the resolved path is outside the `safe_log_root`, it indicates an attempt to access
        # an unauthorized directory or file. To prevent information exposure, the function falls back
        # to archiving the `safe_log_root` itself. This ensures that only authorized log files are archived.
        log_directory_to_archive = safe_log_root

    # --- CWE-552 Fix for output 'logs.tar.gz' location (Information Exposure via Predictable/Public Path) ---
    # The output archive should not be placed in a potentially web-accessible directory
    # like "media/exports", which could lead to unauthorized access to sensitive logs.
    # Instead, the archive is placed in a secure, non-web-accessible, internal directory.
    # This secure path is configurable via an environment variable, with a sensible default for robustness.
    secure_export_dir_str = os.environ.get("APP_SECURE_EXPORT_DIR", str(Path.cwd() / "secure_exports"))
    secure_export_dir = Path(secure_export_dir_str)
    secure_export_dir.mkdir(parents=True, exist_ok=True) # Ensure the secure export directory exists

    # The filename 'logs.tar.gz' is maintained as per the original code's structure and strict rules.
    # Placing it in a securely configured directory effectively addresses the CWE-552 vulnerability
    # regarding the output file's accessibility.
    output = secure_export_dir / "logs.tar.gz"

    # Open the tar archive in write-gzip mode. If the file exists, it will be overwritten.
    with tarfile.open(output, "w:gz") as archive:
        # Add the validated `log_directory_to_archive` to the archive.
        # `arcname="logs"` ensures the top-level directory within the created tarball is named 'logs'.
        # This parameter does not affect the external path and is retained from the original code.
        archive.add(log_directory_to_archive, arcname="logs")
    
    # Return the string representation of the path to the created secure archive.
    return str(output)
