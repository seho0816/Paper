from pathlib import Path
from urllib.parse import unquote


DOWNLOAD_ROOT = Path(
    "/var/app/downloads"
)


def resolve_download_name(
    raw_name: str,
) -> Path:
    decoded_once = unquote(
        raw_name
    )

    if ".." in decoded_once:
        raise ValueError(
            "invalid path"
        )

    decoded_twice = unquote(
        decoded_once
    )

    return (
        DOWNLOAD_ROOT
        / decoded_twice
    )
