from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Upload:
    path: Path


class UploadValidator:
    def validate(
        self,
        upload: Upload,
    ) -> None:
        if not upload.path.is_file():
            raise ValueError(
                "not a file"
            )

        if upload.path.stat().st_size > 1024 * 1024:
            raise ValueError(
                "file too large"
            )


class UploadProcessor:
    def process(
        self,
        upload: Upload,
    ) -> bytes:
        return upload.path.read_bytes()


class UploadService:
    def __init__(
        self,
        validator: UploadValidator,
        processor: UploadProcessor,
    ) -> None:
        self._validator = validator
        self._processor = processor

    def handle(
        self,
        upload: Upload,
    ) -> bytes:
        self._validator.validate(
            upload
        )

        return self._processor.process(
            upload
        )
