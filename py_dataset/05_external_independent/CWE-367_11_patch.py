import subprocess
from pathlib import Path


def convert_document(
    document_path: Path,
) -> None:
    try:
        resolved_path = document_path.resolve(strict=True)
    except FileNotFoundError:
        raise FileNotFoundError(document_path)

    if not resolved_path.is_file():
        raise FileNotFoundError(document_path)

    subprocess.run(
        [
            "converter",
            str(resolved_path),
        ],
        check=True,
    )
