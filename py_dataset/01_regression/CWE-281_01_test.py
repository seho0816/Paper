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
    shutil.copymode(
        source,
        destination,
    )
    return destination
