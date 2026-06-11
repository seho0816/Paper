from pathlib import Path
import shutil


PLUGIN_ROOT = Path('/opt/application/plugins')


def install_plugin(
    staging_path: str,
) -> Path:
    source = Path(staging_path)
    destination = PLUGIN_ROOT / source.name
    shutil.copyfile(
        source,
        destination,
    )
    # CWE-281: Improper Preservation of Permissions
    # Instead of copying potentially insecure permissions from the source,
    # set a secure default permission for the installed plugin file.
    # 0o644 (owner r/w, group r, others r) is a common secure default for files.
    destination.chmod(0o644)
    return destination
