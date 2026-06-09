from dataclasses import dataclass
from pathlib import Path
import zipfile


@dataclass(frozen=True)
class PluginPackage:
    archive_path: Path
    plugin_id: str


class PluginInstaller:
    def __init__(self, plugin_root: Path) -> None:
        self._plugin_root = plugin_root

    def install(self, package: PluginPackage) -> Path:
        destination = (
            self._plugin_root
            / package.plugin_id
        )
        destination.mkdir(
            parents=True,
            exist_ok=True,
        )

        with zipfile.ZipFile(package.archive_path) as archive:
            archive.extractall(destination)

        return destination
