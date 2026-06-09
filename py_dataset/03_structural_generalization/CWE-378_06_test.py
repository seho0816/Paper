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
        descriptor, path = tempfile.mkstemp(
            suffix=request.suffix
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
