from dataclasses import dataclass
from pathlib import Path
import shutil


@dataclass(frozen=True)
class BackupPromotion:
    staged_path: Path
    final_path: Path


class BackupService:
    def promote(
        self,
        request: BackupPromotion,
    ) -> None:
        if request.final_path.exists():
            request.final_path.unlink()

        shutil.move(
            request.staged_path,
            request.final_path,
        )
