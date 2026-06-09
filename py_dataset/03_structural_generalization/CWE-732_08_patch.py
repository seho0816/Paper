import os
from pathlib import Path

class PluginInstaller:
    def install(self, plugin_dir: Path, files: dict[str, bytes]) -> None:
        # Create the directory.
        # The default umask will apply to newly created directories.
        # If the directory already exists, its permissions are not changed by mkdir.
        plugin_dir.mkdir(parents=True, exist_ok=True)
        # Explicitly set secure permissions for the plugin directory.
        # 0o700 grants read, write, and execute permissions only to the owner,
        # preventing unauthorized access or modification.
        os.chmod(plugin_dir, 0o700)
        for name, body in files.items():
            target = plugin_dir / name
            target.write_bytes(body)
            # Explicitly set secure permissions for each plugin file.
            # 0o600 grants read and write permissions only to the owner,
            # preventing unauthorized access or modification.
            os.chmod(target, 0o600)
