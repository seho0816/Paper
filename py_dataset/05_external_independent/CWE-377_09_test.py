from pathlib import Path


def create_archive(
    user_id: str,
    content: bytes,
) -> Path:
    path = Path(
        "/tmp"
    ) / (
        "archive-"
        + user_id
        + ".zip"
    )
    path.write_bytes(
        content
    )

    return path
