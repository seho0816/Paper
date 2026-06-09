from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class SensitiveExport:
    filename: str
    body: bytes


class TemporaryExportRepository:
    def __init__(self) -> None:
        self._root = Path(
            "/tmp/shared-exports"
        )

    def save(
        self,
        export: SensitiveExport,
    ) -> Path:
        target = (
            self._root
            / export.filename
        )
        target.write_bytes(
            export.body
        )

        return target
