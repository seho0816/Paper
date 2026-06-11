import pandas as pd
import os


def export_frame(
    frame: pd.DataFrame,
    output_path: str,
) -> None:
    # CWE-73: External Control of File Name or Path
    # The output_path is controlled externally, allowing an attacker to specify
    # arbitrary file system locations, potentially overwriting critical files or
    # writing to unauthorized directories via path traversal sequences (e.g., '..').

    # Fix: Ensure the output_path is strictly confined to an allowed, secure directory.

    # 1. Define a secure base directory for all exports.
    # This directory should be controlled by the application and not directly by user input.
    # For this example, we create a dedicated 'app_exports' subfolder within the
    # current working directory. In a real application, this would typically be an
    # application-specific data directory (e.g., /var/app/data/exports or a path
    # derived from an application's installation root).
    secure_export_root = os.path.join(os.getcwd(), 'app_exports')

    # Ensure the secure export root directory exists. If it doesn't, create it.
    os.makedirs(secure_export_root, exist_ok=True)

    # 2. Validate the user-provided output_path.
    #    a. Reject absolute paths to prevent direct attempts to write outside the base.
    if os.path.isabs(output_path):
        raise ValueError(f"Absolute paths are not allowed for output: {output_path}")

    #    b. Normalize the path to resolve '..' and '.' components.
    #       This is crucial for identifying path traversal attempts like 'subdir/../file.txt'.
    #       Note: os.path.normpath does not resolve '..' if it starts the path (e.g., '../file.txt').
    normalized_path = os.path.normpath(output_path)

    #    c. Check for explicit path traversal sequences (e.g., starting with '..').
    #       After normalization, if the path still indicates an attempt to go upwards
    #       beyond the intended scope (e.g., ".." or containing "/../"), it's malicious.
    if normalized_path.startswith('..') or os.sep + '..' + os.sep in normalized_path:
        raise ValueError(f"Path traversal sequences are not allowed: {output_path}")

    # 3. Construct the final intended file path by joining the secure root with the validated path.
    #    This ensures that any valid relative path provided by the user (e.g., "reports/data.csv")
    #    is always placed within the 'secure_export_root' hierarchy.
    final_output_path = os.path.join(secure_export_root, normalized_path)

    # 4. Perform a final canonicalization and check to prevent advanced traversal attacks
    #    (e.g., using symbolic links).
    #    os.path.realpath resolves all symbolic links and '..' components, providing the
    #    true, absolute path.
    resolved_final_output_path = os.path.realpath(final_output_path)
    resolved_secure_root = os.path.realpath(secure_export_root)

    # Verify that the resolved final path is indeed within the resolved secure export root.
    # It must start with the secure root path, followed by a directory separator,
    # or be the secure root path itself (if the target is the root directory, though unlikely for files).
    if not (resolved_final_output_path.startswith(resolved_secure_root + os.sep) or
            resolved_final_output_path == resolved_secure_root):
        raise ValueError(
            f"Path traversal detected after resolution: '{output_path}' resolves to "
            f"'{resolved_final_output_path}', which is outside the allowed directory '{resolved_secure_root}'."
        )

    # Use the thoroughly validated and secured path for the file operation.
    frame.to_csv(
        resolved_final_output_path,
        index=False,
    )
