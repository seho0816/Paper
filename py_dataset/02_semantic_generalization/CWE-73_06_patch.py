import uuid
from pathlib import Path

from PIL import Image


def save_thumbnail(
    image: Image.Image,
    requested_path: str,
) -> Path:
    # CWE-73: External Control of File Name or Path
    # The original code directly uses `requested_path` to construct the target path,
    # allowing for directory traversal (e.g., `../../../../etc/passwd`),
    # arbitrary file overwrites, or saving to unintended locations.

    # FIX: Restrict the file saving to a designated safe directory
    # and securely sanitize the filename component from the user-provided path.

    # 1. Define a secure base directory for saving thumbnails.
    #    In a real application, this path would typically be configurable (e.g., from settings or environment variables).
    #    For this example, we use a subdirectory "uploads/thumbnails" relative to the current working directory.
    #    `.resolve()` is used to get the absolute, canonical path. This ensures that the base path is
    #    consistent and prevents issues if the current working directory changes later.
    base_upload_dir = Path("./uploads/thumbnails").resolve()

    # 2. Ensure the base directory exists.
    #    `parents=True` creates any necessary parent directories, and `exist_ok=True` prevents an error
    #    if the directory already exists.
    base_upload_dir.mkdir(parents=True, exist_ok=True)

    # 3. Securely sanitize the filename from `requested_path`.
    #    `Path(requested_path).name` extracts only the final path component (e.g., 'image.png' from 'dir/image.png').
    #    This effectively strips away any directory components (like `../` or `/absolute/path/`) and prevents
    #    most directory traversal attempts.
    processed_filename = Path(requested_path).name
    original_suffix = Path(requested_path).suffix

    # Additional sanitization: If the extracted filename is empty, '.', or '..',
    # it's considered unsafe and could lead to saving directly to a directory
    # or its parent. In such cases, generate a unique, safe filename.
    if not processed_filename or processed_filename == "." or processed_filename == "..":
        # Generate a unique ID to ensure a valid, non-colliding filename.
        # This is a robust way to handle problematic user-provided filenames while
        # adhering to the security principle of preventing arbitrary path control.
        unique_id = uuid.uuid4().hex
        if original_suffix:
            safe_filename = f"{unique_id}{original_suffix}"
        else:
            safe_filename = unique_id
    else:
        # If the filename is generally safe after extracting the name, use it.
        # Further character-level sanitization (e.g., removing spaces or special characters)
        # could be added here if specific naming conventions are required,
        # but Path.name already addresses the core path traversal vulnerability.
        safe_filename = processed_filename

    # 4. Construct the final target path by securely joining the base directory with the safe filename.
    #    This guarantees that the file will be saved exclusively within `base_upload_dir`,
    #    preventing external control of the file's location.
    target = base_upload_dir / safe_filename

    # The image is then saved to this securely constructed path.
    image.save(
        target,
    )

    # Return the path where the image was actually saved.
    return target
