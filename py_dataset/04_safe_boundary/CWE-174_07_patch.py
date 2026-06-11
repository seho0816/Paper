from pathlib import Path
from urllib.parse import unquote


DOWNLOAD_ROOT = Path(
    "/var/app/downloads"
).resolve()


def resolve_download_name(
    raw_name: str,
) -> Path:
    decoded = unquote(
        raw_name
    )

    if unquote(
        decoded
    ) != decoded:
        raise ValueError(
            "multiple encoding denied"
        )

    target = (
        DOWNLOAD_ROOT
        / decoded
    ).resolve()

    target.relative_to(
        DOWNLOAD_ROOT
    )

    return target

