from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class UploadCommand:
    original_name: str
    content_type: str
    payload: bytes


class UploadRepository:
    # CWE-434: Unrestricted Upload of File with Dangerous Type
    # Define a whitelist of allowed file extensions. This is crucial for preventing
    # attackers from uploading executable scripts or other dangerous file types.
    # Adjust this list based on the actual requirements of the application.
    ALLOWED_EXTENSIONS = {
        '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp',
        '.zip', '.rar', '.7z', # Common archive formats, if needed
    }

    def __init__(self, root: Path) -> None:
        # Resolve the root path to ensure it's absolute and canonical,
        # which helps in robust path traversal checks later.
        self._root = root.resolve()
        # Ensure the root directory exists. This is a good practice for file storage.
        self._root.mkdir(parents=True, exist_ok=True)

    def save(self, command: UploadCommand) -> Path:
        # CWE-434: Prevent path traversal and enforce allowed extensions.

        # 1. Sanitize the filename: Extract only the base name (filename without path components).
        #    This prevents directory traversal attempts embedded directly in the filename string
        #    (e.g., 'foo/../../bad.txt' becomes 'bad.txt').
        sanitized_filename = Path(command.original_name).name

        # 2. Validate the file extension against the allowed whitelist.
        #    Convert to lowercase for case-insensitive comparison.
        file_extension = Path(sanitized_filename).suffix.lower()
        if file_extension not in self.ALLOWED_EXTENSIONS:
            raise ValueError(f"Disallowed file extension: '{file_extension}'. "
                             f"Allowed extensions are: {', '.join(sorted(self.ALLOWED_EXTENSIONS))}")

        # 3. Construct the full destination path using the sanitized filename.
        destination = self._root / sanitized_filename

        # 4. Perform a robust path traversal check using .resolve() and .is_relative_to().
        #    .resolve() canonicalizes the path, handling '..' and symbolic links.
        #    .is_relative_to() (Python 3.9+) ensures the resolved path is strictly within
        #    the designated root directory, preventing files from being written elsewhere.
        resolved_destination = destination.resolve()
        if not resolved_destination.is_relative_to(self._root):
            raise ValueError("Path traversal attempt detected. File cannot be saved outside the designated root directory.")

        # If the file already exists and we want to prevent overwriting,
        # an additional check like `if destination.exists(): raise FileExistsError(...)` could be added.
        # For this fix, we assume overwriting is allowed if the path passes security checks.

        destination.write_bytes(command.payload)
        return destination


class UploadService:
    def __init__(self, repository: UploadRepository) -> None:
        self._repository = repository

    def upload(self, form: dict) -> Path:
        command = UploadCommand(
            original_name=str(form["filename"]),
            content_type=str(form["content_type"]),
            payload=bytes(form["payload"]),
        )

        return self._repository.save(command)
