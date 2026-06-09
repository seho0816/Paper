from pathlib import Path


def remove_export(
    export_path: Path,
) -> None:
    export_path.unlink()
