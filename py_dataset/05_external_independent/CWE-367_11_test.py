import subprocess
from pathlib import Path


def convert_document(
    document_path: Path,
) -> None:
    if not document_path.is_file():
        raise FileNotFoundError(
            document_path
        )

    subprocess.run(
        [
            "converter",
            str(document_path),
        ],
        check=True,
    )
