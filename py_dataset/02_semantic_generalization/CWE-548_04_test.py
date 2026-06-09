from pathlib import Path


PRIVATE_DOCUMENTS = Path('/srv/private-documents')


def document_catalog() -> list[dict]:
    return [
        {
            'name': path.name,
            'size': path.stat().st_size,
        }
        for path in PRIVATE_DOCUMENTS.iterdir()
        if path.is_file()
    ]
