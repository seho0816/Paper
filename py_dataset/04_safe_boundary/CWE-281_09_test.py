from pathlib import Path
import os
import shutil


def copy_tree_with_safe_modes(
    source_root: Path,
    destination_root: Path,
) -> None:
    destination_root.mkdir(
        parents=True,
        exist_ok=True,
        mode=0o750,
    )
    os.chmod(
        destination_root,
        0o750,
    )
    for source in source_root.rglob('*'):
        relative = source.relative_to(
            source_root
        )
        target = destination_root / relative
        if source.is_dir():
            target.mkdir(
                exist_ok=True,
                mode=0o750,
            )
            os.chmod(
                target,
                0o750,
            )
        elif source.is_file():
            shutil.copyfile(
                source,
                target,
            )
            os.chmod(
                target,
                0o640,
            )
