import shutil
from pathlib import Path


class PluginPublisher:
    def __init__(self, publish_root: Path) -> None:
        self.publish_root = publish_root

    def publish(self, uploaded_plugin: Path) -> Path:
        destination = self.publish_root / uploaded_plugin.name
        shutil.copy2(uploaded_plugin, destination)
        return destination
