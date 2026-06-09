from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ExportLocation:
    tenant_id: str
    category: str


class ExportDirectoryRepository:
    def __init__(
        self,
        shared_root: Path,
    ) -> None:
        self._shared_root = shared_root

    def initialize(
        self,
        location: ExportLocation,
    ) -> Path:
        directory = (
            self._shared_root
            / location.tenant_id
            / location.category
        )
        directory.mkdir(
            parents=True,
            exist_ok=True,
        )
        return directory
