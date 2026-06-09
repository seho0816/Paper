import hashlib
from pathlib import Path


def verify_release(
    release_path: Path,
    expected_digest: str,
) -> bool:
    actual_digest = hashlib.sha256(
        release_path.read_bytes()
    ).hexdigest()

    return (
        actual_digest
        == expected_digest
    )
