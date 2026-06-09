import os
from pathlib import Path

class PluginInstaller:
    def install(self, plugin_dir: Path, files: dict[str, bytes]) -> None:
        plugin_dir.mkdir(parents=True, exist_ok=True)
        os.chmod(plugin_dir, 0o777)
        for name, body in files.items():
            target = plugin_dir / name
            target.write_bytes(body)
            os.chmod(target, 0o777)
