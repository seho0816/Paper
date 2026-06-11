import hashlib
from pathlib import Path


def validate_upload(
    file_path: Path,
    checksum_path: Path,
) -> bool:
    if not checksum_path.is_file():
        return False

    expected = checksum_path.read_text(
        encoding="utf-8"
    ).strip()
    actual = hashlib.sha256(
        file_path.read_bytes()
    ).hexdigest()

    return actual == expected
