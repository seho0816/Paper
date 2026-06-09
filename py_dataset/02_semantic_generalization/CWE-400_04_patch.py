import hashlib
from pathlib import Path


def hash_directory(
    root: Path,
) -> dict[str, str]:
    results = {}

    for path in root.rglob("*"):
        if path.is_file():
            # CWE-400 fix: Read the file in chunks to prevent excessive memory consumption
            # when hashing very large files, avoiding a potential Denial of Service.
            hasher = hashlib.sha256()
            with open(path, "rb") as f:
                while True:
                    chunk = f.read(4096)  # Read in 4KB chunks
                    if not chunk:
                        break  # End of file
                    hasher.update(chunk)
            results[str(path)] = hasher.hexdigest()

    return results
