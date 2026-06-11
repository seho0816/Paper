from pathlib import Path


MAX_SIZE = 5 * 1024 * 1024


def load_small_file(
    path: Path,
) -> bytes:
    # To prevent a Time-of-check to Time-of-use (TOCTOU) vulnerability (CWE-367),
    # open the file first to obtain a stable reference (file descriptor).
    # All subsequent operations (size check, reading) are performed on this
    # opened file descriptor, ensuring that the same file is acted upon.
    with path.open("rb") as f:
        # Get the size of the *opened* file.
        # Seek to the end of the file to get its current position, which is the size.
        f.seek(0, 2)  # Seek to the end of the file (os.SEEK_END)
        current_size = f.tell()  # Get the current position, which is the file size
        f.seek(0)  # Seek back to the beginning of the file for reading

        if current_size > MAX_SIZE:
            raise ValueError(
                "file too large"
            )

        return f.read()
