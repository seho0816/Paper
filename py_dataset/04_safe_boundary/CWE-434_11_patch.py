from io import BytesIO
from pathlib import Path
import secrets

from PIL import Image

UPLOAD_ROOT = Path("/srv/private-images")


def save_verified_image(
    content: bytes,
) -> Path:
    with Image.open(BytesIO(content)) as image:
        image.verify()
        image_format = image.format

        extension_by_format = {
            "PNG": ".png",
            "JPEG": ".jpg",
        }
        extension = extension_by_format.get(
            image_format,
        )

        if extension is None:
            raise ValueError("unsupported image")

        destination = (
            UPLOAD_ROOT
            / f"{secrets.token_hex(16)}{extension}"
        )
        # CWE-434 fix: Re-encode the image to ensure only valid image data is written.
        # This strips any potentially malicious data appended after the image header.
        image.save(destination, format=image_format)

    return destination
