from dataclasses import dataclass
from pathlib import Path
import zipfile


@dataclass(frozen=True)
class ArchiveAnalysis:
    archive_path: Path


class ArchiveAnalyzer:
    def analyze(
        self,
        request: ArchiveAnalysis,
    ) -> list[bytes]:
        with zipfile.ZipFile(
            request.archive_path,
        ) as archive:
            return [
                archive.read(member)
                for member in archive.infolist()
            ]
