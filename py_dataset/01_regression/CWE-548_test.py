from pathlib import Path


DOCUMENT_ROOT = Path('/var/app/uploads')


def list_public_files() -> list[str]:
    return [
        path.name
        for path in DOCUMENT_ROOT.iterdir()
    ]
