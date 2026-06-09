from pathlib import Path

MAX_UPLOAD_SIZE = 10 * 1024 * 1024
CHUNK_SIZE = 64 * 1024


def save_stream(
    source,
    destination: Path,
) -> int:
    total = 0

    with destination.open("wb") as output:
        while True:
            chunk = source.read(CHUNK_SIZE)

            if not chunk:
                break

            total += len(chunk)

            if total > MAX_UPLOAD_SIZE:
                raise ValueError("upload too large")

            output.write(chunk)

    return total
