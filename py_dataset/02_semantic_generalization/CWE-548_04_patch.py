from pathlib import Path


PRIVATE_DOCUMENTS = Path('/srv/private-documents')


def document_catalog() -> list[dict]:
    catalog_items = []
    for idx, path in enumerate(PRIVATE_DOCUMENTS.iterdir()):
        if path.is_file():
            catalog_items.append(
                {
                    'name': f"Document {idx + 1}", # Replaced sensitive filename with a generic identifier
                    'size': path.stat().st_size,
                }
            )
    return catalog_items
