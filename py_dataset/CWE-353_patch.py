import json
import zipfile


class PartnerCatalogImporter:
    def import_bundle(self, archive_path: str) -> int:
        # Define a maximum allowed size for catalog.json to prevent resource exhaustion (DoS).
        # This acts as a validation step for the input data extracted from the archive.
        MAX_CATALOG_FILE_SIZE = 10 * 1024 * 1024  # 10 MB

        with zipfile.ZipFile(archive_path) as archive:
            try:
                # Get information about the 'catalog.json' file within the archive
                catalog_info = archive.getinfo("catalog.json")
            except KeyError:
                # If 'catalog.json' is not found, raise an error as it's a required file.
                raise ValueError("archive does not contain catalog.json")

            # Validate the uncompressed size of 'catalog.json'
            if catalog_info.file_size > MAX_CATALOG_FILE_SIZE:
                raise ValueError(
                    f"catalog.json exceeds maximum allowed size of "
                    f"{MAX_CATALOG_FILE_SIZE} bytes (found: {catalog_info.file_size} bytes)"
                )

            catalog_bytes = archive.read("catalog.json")

        catalog = json.loads(catalog_bytes)
        return save_catalog_rows(catalog["items"])


def save_catalog_rows(items: list[dict]) -> int:
    return len(items)
