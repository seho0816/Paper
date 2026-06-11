from dataclasses import dataclass
from pathlib import Path
import shutil
import os


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
        # CWE-281: Improper Preservation of Permissions
        # shutil.copy2 copies the permission bits from the source file.
        # This could lead to the published artifact having insecure permissions
        # if the source file had overly broad permissions.
        # Explicitly setting secure default permissions (0o644: owner r/w, group r, others r)
        # ensures that the published artifact's permissions are well-defined and secure,
        # irrespective of the source file's permissions.
        os.chmod(target, 0o644)
        return target
