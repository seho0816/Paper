import shutil
from pathlib import Path
import os


class PluginPublisher:
    def __init__(self, publish_root: Path) -> None:
        self.publish_root = publish_root

    def publish(self, uploaded_plugin: Path) -> Path:
        destination = self.publish_root / uploaded_plugin.name
        # CWE-281: Improper Preservation of Permissions
        # shutil.copy2 preserves all metadata, including potentially malicious permissions.
        # Use shutil.copyfile to only copy file content, then explicitly set safe permissions.
        shutil.copyfile(uploaded_plugin, destination)
        # Set safe default permissions (e.g., owner read/write, group/others read-only)
        # This prevents the propagation of potentially dangerous permissions (e.g., world-writable or executable)
        # from the untrusted uploaded_plugin.
        os.chmod(destination, 0o644)
        return destination
