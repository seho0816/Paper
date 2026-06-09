from dataclasses import dataclass
from pathlib import Path
import shutil


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
        destination = (
            self._public_root
            / upload.original_name
        )
        shutil.move(
            upload.temporary_path,
            destination,
        )
        self._scanner.scan(destination)

        return destination
