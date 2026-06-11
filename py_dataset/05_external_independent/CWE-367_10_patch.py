from pathlib import Path


def store_media(
    media_root: Path,
    filename: str,
    content: bytes,
) -> Path:
    target = (
        media_root
        / filename
    )

    # CWE-367 (Time-of-check Time-of-use - TOCTOU) fix:
    # Use 'x' mode for open() to ensure atomic file creation.
    # This mode exclusively creates a new file; if the file already exists,
    # it raises a FileExistsError, preventing a race condition
    # where a malicious actor could replace the target with a symlink
    # between the existence check and the write operation.
    try:
        with open(target, 'xb') as f:
            f.write(content)
    except FileExistsError:
        # If open('xb') raises FileExistsError, it means the file already exists.
        # This behavior is consistent with the original code's explicit
        # 'if target.exists(): raise FileExistsError'.
        raise FileExistsError(target)

    return target
