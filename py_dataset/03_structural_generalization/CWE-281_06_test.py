from dataclasses import dataclass
from pathlib import Path
import shutil


@dataclass(frozen=True)
class Artifact:
    source_path: Path
    display_name: str


class ArtifactPublisher:
    def __init__(
        self,
        publish_root: Path,
    ) -> None:
        self._publish_root = publish_root

    def publish(
        self,
        artifact: Artifact,
    ) -> Path:
        target = (
            self._publish_root
            / artifact.display_name
        )
        shutil.copy2(
            artifact.source_path,
            target,
        )
        return target
