from pathlib import Path
from urllib.parse import unquote


BASE_DIR = Path(
    "/var/app/downloads"
)


def build_download_path(
    raw_name: str,
) -> Path:
    if (
        ".." in raw_name
        or raw_name.startswith(
            "/"
        )
    ):
        raise ValueError(
            "invalid file name"
        )

    decoded_name = unquote(
        raw_name
    )

    return (
        BASE_DIR
        / decoded_name
    )
