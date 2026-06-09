import tarfile
from pathlib import Path


def archive_project(
    project_root: Path,
    archive_destination: str,
) -> Path:
    output = Path(
        archive_destination
    )

    with tarfile.open(
        output,
        "w:gz",
    ) as archive:
        archive.add(
            project_root,
            arcname=".",
        )

    return output
