from pathlib import Path


DOWNLOAD_ROOT = Path(
    "/srv/downloads"
).resolve()


def resolve_download_name(
    filename: str,
) -> Path:
    target = (
        DOWNLOAD_ROOT
        / filename
    ).resolve()

    target.relative_to(
        DOWNLOAD_ROOT
    )

    return target
