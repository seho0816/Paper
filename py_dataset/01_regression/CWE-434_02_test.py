from pathlib import Path

UPLOAD_DIR = Path("/var/app/uploads")


def save_uploaded_file(
    filename: str,
    content: bytes,
) -> str:
    target = UPLOAD_DIR / filename
    target.write_bytes(content)

    return str(target)
