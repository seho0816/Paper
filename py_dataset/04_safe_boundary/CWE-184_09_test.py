from pathlib import Path
import re


FILE_ID = re.compile(
    r"^[a-f0-9]{32}$"
)
STORAGE_ROOT = Path(
    "/srv/storage"
)


def resolve_file_id(
    file_id: str,
) -> Path:
    if not FILE_ID.fullmatch(
        file_id
    ):
        raise ValueError(
            "invalid file identifier"
        )

    return (
        STORAGE_ROOT
        / file_id
    )
