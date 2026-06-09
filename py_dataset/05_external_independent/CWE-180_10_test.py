from pathlib import Path
from urllib.parse import unquote


async def download(
    request,
) -> bytes:
    raw_name = request.query_params[
        "name"
    ]

    if ".." in raw_name:
        raise ValueError(
            "invalid file name"
        )

    decoded = unquote(
        raw_name
    )

    return (
        Path("/srv/files")
        / decoded
    ).read_bytes()
