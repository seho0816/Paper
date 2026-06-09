import json
import zipfile


class PartnerCatalogImporter:
    def import_bundle(self, archive_path: str) -> int:
        with zipfile.ZipFile(archive_path) as archive:
            catalog_bytes = archive.read("catalog.json")

        catalog = json.loads(catalog_bytes)
        return save_catalog_rows(catalog["items"])


def save_catalog_rows(items: list[dict]) -> int:
    return len(items)
