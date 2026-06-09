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

    # CWE-434 fix: Use the detected image_type for the saved file's extension
    # instead of the potentially user-controlled 'extension' from original_name.
    # This ensures the file is saved with a safe extension corresponding to its
    # actual content type, mitigating risks if the original_name was spoofed.
    destination = (
        UPLOAD_ROOT
        / f"{secrets.token_hex(16)}.{image_type}"
    )
    destination.write_bytes(content)

    return destination
