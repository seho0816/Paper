import hashlib
from pathlib import Path


def hash_directory(
    root: Path,
) -> dict[str, str]:
    results = {}

    for path in root.rglob("*"):
        if path.is_file():
            results[str(path)] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()

    return results
