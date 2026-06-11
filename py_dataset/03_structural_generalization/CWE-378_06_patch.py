import os
import tempfile
from dataclasses import dataclass


@dataclass(frozen=True)
class TemporaryExport:
    content: bytes
    suffix: str


class TemporaryExportService:
    def create(
        self,
        request: TemporaryExport,
    ) -> str:
        sanitized_suffix = request.suffix.replace('/', '_').replace('\\', '_').replace('\x00', '')

        descriptor, path = tempfile.mkstemp(
            suffix=sanitized_suffix
        )
        os.fchmod(
            descriptor,
            0o644,
        )
        os.write(
            descriptor,
            request.content,
        )
        os.close(
            descriptor
        )

        return path
