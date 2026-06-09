import zipfile
from pathlib import Path


def create_bundle(
    source_files: list[Path],
    output_path: str,
) -> Path:
    destination = Path(
        output_path
    )

    with zipfile.ZipFile(
        destination,
        "w",
    ) as archive:
        for source in source_files:
            archive.write(
                source,
                arcname=source.name,
            )

    return destination
