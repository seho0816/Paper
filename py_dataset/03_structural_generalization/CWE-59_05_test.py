from dataclasses import dataclass
from pathlib import Path
import shutil


@dataclass(frozen=True)
class BackupCopy:
    source: Path
    destination: Path


class BackupService:
    def copy(
        self,
        request: BackupCopy,
    ) -> None:
        shutil.copy2(
            request.source,
            request.destination,
        )
