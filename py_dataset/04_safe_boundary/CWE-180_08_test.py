from pathlib import Path
from urllib.parse import unquote


BASE_DIR = Path(
    "/var/app/downloads"
).resolve()


def build_download_path(
    raw_name: str,
) -> Path:
    decoded_name = unquote(
        raw_name
    )
    target = (
        BASE_DIR
        / decoded_name
    ).resolve()

    target.relative_to(
        BASE_DIR
    )

    return target
