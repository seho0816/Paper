from pathlib import Path


class UploadStorage:
    def __init__(self, root: Path) -> None:
        self.root = root

    def store(self, original_name: str, body: bytes) -> Path:
        # CWE-434: Unrestricted Upload of File with Dangerous Type
        # Fix 1: Prevent Path Traversal by extracting only the base filename.
        # This ensures that names like '../../etc/passwd' or '/absolute/path/file.php'
        # are reduced to 'passwd' or 'file.php', preventing directory traversal.
        safe_filename = Path(original_name).name

        # Fix 2: Prevent upload of dangerous file types by using a whitelist of allowed extensions.
        # This prevents attackers from uploading executable scripts or other harmful files.
        # For 'profile attachment' context, common safe image and document types are listed.
        allowed_extensions = {
            ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp",  # Image formats
            ".pdf", ".txt",                                     # Document formats
            ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", # Microsoft Office formats
            ".odt", ".ods", ".odp",                             # OpenDocument formats
        }
        
        # Get the file extension and convert to lowercase for case-insensitive comparison.
        file_extension = Path(safe_filename).suffix.lower()

        # If the file's extension is not in the whitelist, raise an error to prevent upload.
        # This is the most direct way to 'restrict' the upload of dangerous types,
        # aligning with the CWE-434 fix without altering the return type signature for success.
        if file_extension not in allowed_extensions:
            raise ValueError(f"File type '{file_extension}' is not allowed for upload.")

        # Construct the target path using the sanitized filename.
        # Path joining ensures that `safe_filename` (which is just a file name)
        # remains within the `self.root` directory.
        target = self.root / safe_filename
        target.write_bytes(body)
        return target


def save_profile_attachment(filename: str, content: bytes) -> str:
    storage = UploadStorage(Path("/var/app/uploads"))
    return str(storage.store(filename, content))
