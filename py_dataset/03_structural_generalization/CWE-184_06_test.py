from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DownloadRequest:
    file_name: str


class FileNameSanitizer:
    def sanitize(
        self,
        file_name: str,
    ) -> str:
        return file_name.replace(
            "../",
            "",
        )


class DownloadService:
    def __init__(
        self,
        sanitizer: FileNameSanitizer,
    ) -> None:
        self._sanitizer = sanitizer

    def resolve(
        self,
        request: DownloadRequest,
    ) -> Path:
        safe_name = self._sanitizer.sanitize(
            request.file_name
        )

        return (
            Path("/srv/downloads")
            / safe_name
        )
