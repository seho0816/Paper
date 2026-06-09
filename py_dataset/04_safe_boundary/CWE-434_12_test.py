import secrets
from pathlib import Path

MAX_FILE_SIZE = 5 * 1024 * 1024
UPLOAD_ROOT = Path("/srv/private-documents")


def save_pdf(
    content: bytes,
) -> Path:
    if len(content) > MAX_FILE_SIZE:
        raise ValueError("file too large")

    if not content.startswith(b"%PDF-"):
        raise ValueError("invalid PDF")

    destination = (
        UPLOAD_ROOT
        / f"{secrets.token_hex(16)}.pdf"
    )
    destination.write_bytes(content)

    return destination
