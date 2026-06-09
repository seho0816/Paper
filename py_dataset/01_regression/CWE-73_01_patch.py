import os

def save_snapshot(
    filename: str,
    content: bytes,
) -> None:
    # Define a safe base directory for file operations.
    # In the absence of a specific configured directory, the current working directory is used as the implicit base.
    # This ensures that files are saved within a controlled area and prevents arbitrary file system writes.
    base_dir = os.getcwd()

    # Step 1: Combine the base directory with the user-provided filename.
    # This creates a full path that will then be canonicalized.
    # Note: On POSIX systems, if `filename` is an absolute path (e.g., "/etc/passwd"),
    # `os.path.join(base_dir, filename)` will result in `filename` itself.
    # This behavior is correctly handled by the subsequent path validation steps.
    combined_path = os.path.join(base_dir, filename)

    # Step 2: Canonicalize the combined path.
    # os.path.realpath resolves all '..' (parent directory) components and symbolic links,
    # converting the path into its absolute, normalized, and actual location on the filesystem.
    resolved_path = os.path.realpath(combined_path)

    # Step 3: Canonicalize the base directory for comparison.
    # This is crucial to ensure we compare two fully resolved and unambiguous paths.
    resolved_base_dir = os.path.realpath(base_dir)

    # Step 4: Verify that the resolved_path is located within the resolved_base_dir.
    # This prevents path traversal attacks (e.g., `../../../etc/passwd`) and attempts to write
    # to absolute paths outside the intended scope (e.g., `/etc/passwd`).
    # The `+ os.sep` ensures that a file named `base_dir_suffix.txt` in the parent directory
    # is not considered to be inside `base_dir`.
    # It also handles the case where resolved_path *is* the base_dir (e.g., if filename was '.').
    if not resolved_path.startswith(resolved_base_dir + os.sep) and resolved_path != resolved_base_dir:
        raise ValueError("Path traversal attempt detected: File cannot be saved outside the designated directory.")

    # Step 5: Prevent writing directly to a directory.
    # The function is intended to save a snapshot to a *file*, not overwrite a directory or
    # create a file with the same name as an existing directory.
    if os.path.exists(resolved_path) and os.path.isdir(resolved_path):
        raise ValueError("Cannot write to a directory.")

    # If all checks pass, the resolved_path is deemed safe for file writing.
    with open(
        resolved_path,
        "wb",
    ) as output:
        output.write(
            content
        )
