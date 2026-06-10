from pathlib import Path
from urllib.parse import unquote


DOWNLOAD_ROOT = Path("/srv/app/downloads")


class DownloadPathResolver:
    def resolve(self, requested_name: str) -> Path:
        if ".." in requested_name or requested_name.startswith("/"):
            raise ValueError("invalid name")

        decoded_name = unquote(requested_name)
        return DOWNLOAD_ROOT / decoded_name


def build_file_response_path(name_from_query: str) -> Path:
    resolver = DownloadPathResolver()
    return resolver.resolve(name_from_query)
