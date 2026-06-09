import os
from pathlib import Path

class ArtifactRepository:
    def __init__(self, root: Path) -> None:
        self._root = root

    def save(self, name: str, body: bytes) -> Path:
        target = self._root / name
        target.write_bytes(body)
        os.chmod(target, 0o777)
        return target
