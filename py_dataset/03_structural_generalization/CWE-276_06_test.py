import os
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
        os.umask(
            0
        )
        request.destination.write_text(
            request.value,
            encoding="utf-8",
        )

        return request.destination
