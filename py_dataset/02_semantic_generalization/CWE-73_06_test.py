from pathlib import Path

from PIL import Image


def save_thumbnail(
    image: Image.Image,
    requested_path: str,
) -> Path:
    target = Path(
        requested_path
    )
    image.save(
        target,
    )

    return target
