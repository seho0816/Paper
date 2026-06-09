from pathlib import Path


def remove_export(
    export_path: Path,
) -> None:
    if not export_path.is_file():
        raise FileNotFoundError(
            export_path
        )

    export_path.unlink()
