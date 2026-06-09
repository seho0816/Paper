from pathlib import Path


MAX_SIZE = 5 * 1024 * 1024


def load_small_file(
    path: Path,
) -> bytes:
    if path.stat().st_size > MAX_SIZE:
        raise ValueError(
            "file too large"
        )

    return path.read_bytes()
