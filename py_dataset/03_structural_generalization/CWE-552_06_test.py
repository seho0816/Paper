from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class BackupArtifact:
    name: str
    content: bytes


class PublicBackupRepository:
    def __init__(self) -> None:
        self._root = Path("static") / "backups"

    def save(self, artifact: BackupArtifact) -> Path:
        self._root.mkdir(parents=True, exist_ok=True)
        target = self._root / artifact.name
        target.write_bytes(artifact.content)
        return target
