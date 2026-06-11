import os
import io
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SecretExport:
    destination: Path
    value: str


class SecretExportService:
    def export(
        self,
        request: SecretExport,
    ) -> Path:
        SECURE_FILE_MODE = 0o600

        fd = os.open(request.destination, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, SECURE_FILE_MODE)
        try:
            with io.TextIOWrapper(os.fdopen(fd, 'wb'), encoding="utf-8") as f:
                f.write(request.value)
        finally:
            pass

        return request.destination
