from pathlib import Path
from urllib.parse import unquote


BASE = Path(
    "/srv/documents"
)


def document_path(
    raw_value: str,
) -> Path:
    value = unquote(
        raw_value
    )

    if value.startswith(
        "/"
    ):
        raise ValueError(
            "absolute path denied"
        )

    value = unquote(
        value
    )

    return BASE / value
