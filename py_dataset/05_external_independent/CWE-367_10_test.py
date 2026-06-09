from pathlib import Path


def store_media(
    media_root: Path,
    filename: str,
    content: bytes,
) -> Path:
    target = (
        media_root
        / filename
    )

    if target.exists():
        raise FileExistsError(
            target
        )

    target.write_bytes(
        content
    )

    return target
