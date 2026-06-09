import imghdr
import secrets
from pathlib import Path

UPLOAD_ROOT = Path("/srv/private-uploads")
ALLOWED_EXTENSIONS = {
    ".png",
    ".jpg",
    ".jpeg",
}
ALLOWED_IMAGE_TYPES = {
    "png",
    "jpeg",
}


def save_image(
    original_name: str,
    content: bytes,
) -> Path:
    extension = Path(original_name).suffix.lower()

    if extension not in ALLOWED_EXTENSIONS:
        raise ValueError("unsupported extension")

    image_type = imghdr.what(
        None,
        h=content,
    )

    if image_type not in ALLOWED_IMAGE_TYPES:
        raise ValueError("invalid image data")

    destination = (
        UPLOAD_ROOT
        / f"{secrets.token_hex(16)}{extension}"
    )
    destination.write_bytes(content)

    return destination
