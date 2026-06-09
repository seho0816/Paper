import os
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
        # This initial validation provides a quick fail mechanism
        # but is susceptible to TOCTOU if the file changes after this check.
        # The robust TOCTOU protection is applied in UploadProcessor.
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
        # Mitigate TOCTOU by opening the file securely and checking its properties
        # on the opened file descriptor before reading.
        fd = -1  # Initialize file descriptor to an invalid value
        try:
            # 1. Open the file descriptor with O_NOFOLLOW to prevent symlink attacks.
            # O_RDONLY is implicitly included for 'rb' mode.
            fd = os.open(upload.path, os.O_RDONLY | os.O_NOFOLLOW)

            # 2. Perform checks on the opened file descriptor to prevent TOCTOU
            # where file properties (like size) change between validation and use.
            fstat = os.fstat(fd)
            if fstat.st_size > 1024 * 1024:
                raise ValueError("file too large")

            # 3. Read bytes from the securely opened file descriptor.
            with os.fdopen(fd, 'rb') as f:
                return f.read()

        except OSError as e:
            # Handle specific OS errors that might indicate file issues relevant to validation
            if e.errno in (os.errno.ENOENT, os.errno.EISDIR):
                # File not found (ENOENT) or path is a directory (EISDIR)
                raise ValueError("not a file") from e
            if e.errno == os.errno.ELOOP:
                # Path is a symbolic link and O_NOFOLLOW was used, which is a security feature.
                raise ValueError("path is a symbolic link") from e
            # Re-raise any other unexpected OS errors
            raise
        finally:
            # Ensure the file descriptor is closed if it was successfully opened
            if fd != -1:
                os.close(fd)


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
        # Initial validation provides quick feedback and filters obvious issues.
        # The critical TOCTOU protection happens during the processor's access.
        self._validator.validate(
            upload
        )

        return self._processor.process(
            upload
        )
