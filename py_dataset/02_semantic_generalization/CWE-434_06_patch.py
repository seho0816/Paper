import base64
from pathlib import Path


def save_attachment(payload: dict) -> str:
    original_filename = str(payload["filename"])
    encoded_content = str(payload["content"])
    content = base64.b64decode(
        encoded_content,
    )

    # --- CWE-434 Fix Start ---
    # To mitigate CWE-434 (Unrestricted Upload of File with Dangerous Type),
    # we need to sanitize the filename to prevent malicious file extensions and path traversal.

    # 1. Prevent path traversal by extracting only the base filename.
    #    This strips any directory components (e.g., '../', '/') from the filename.
    clean_filename_part = Path(original_filename).name

    # 2. Define a whitelist of allowed file extensions.
    #    These are generally considered safe for static file serving and common attachments.
    allowed_extensions = {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".tiff", ".webp", # Image formats
        ".pdf", ".txt", ".rtf", # Document formats
        ".csv", ".tsv", # Data formats
        ".zip", ".tar", ".gz", ".bz2", ".7z", # Archive formats (generally not executable by web servers)
    }

    # 3. Extract the file extension from the cleaned filename.
    #    Path().suffix handles extensions correctly, e.g., '.gz' for 'archive.tar.gz'.
    file_extension = Path(clean_filename_part).suffix.lower()

    # 4. Validate the file extension against the whitelist.
    #    If the extension is not in the allowed list, replace it with a safe default extension.
    if file_extension not in allowed_extensions:
        # Get the filename without its original extension (e.g., 'document.pdf' -> 'document').
        # If there was no extension, Path().stem returns the whole filename.
        file_stem = Path(clean_filename_part).stem
        # Append a safe default extension like '.bin' (binary file) to prevent execution.
        filename = file_stem + ".bin"
    else:
        # If the extension is allowed, use the cleaned filename as is.
        filename = clean_filename_part
    # --- CWE-434 Fix End ---

    destination = (
        Path("/srv/web/public/attachments")
        / filename
    )
    destination.write_bytes(content)

    return str(destination)
