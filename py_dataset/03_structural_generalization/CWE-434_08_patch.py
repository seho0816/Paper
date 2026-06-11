from dataclasses import dataclass
from pathlib import Path
import shutil
import uuid


# Assuming antivirus_scan is defined elsewhere or is a global mock for testing.
# For a fully runnable, self-contained snippet, we define it here minimally.
def antivirus_scan(path: Path) -> bool:
    """
    Mock function for an antivirus scanner.
    In a real scenario, this would interface with an actual AV engine.
    """
    return True


@dataclass(frozen=True)
class ImageUpload:
    temporary_path: Path
    original_name: str


class ImageScanner:
    def scan(self, path: Path) -> bool:
        return antivirus_scan(path)


class ImageService:
    def __init__(
        self,
        scanner: ImageScanner,
        public_root: Path,
    ) -> None:
        self._scanner = scanner
        self._public_root = public_root

    def publish(self, upload: ImageUpload) -> Path:
        ALLOWED_IMAGE_EXTENSIONS = {'.jpg', '.jpeg', '.png', '.gif', '.webp'}

        original_name_path = Path(upload.original_name)
        file_extension = original_name_path.suffix.lower()

        if not file_extension or file_extension not in ALLOWED_IMAGE_EXTENSIONS:
            raise ValueError(f"Unsupported file type: {file_extension}. Only image files are allowed.")

        safe_file_name = f"{uuid.uuid4()}{file_extension}"

        destination = (
            self._public_root
            / safe_file_name
        )
        shutil.move(
            upload.temporary_path,
            destination,
        )
        self._scanner.scan(destination)

        return destination
