import tempfile
from pathlib import Path


def write_sensitive_snapshot(
    content: bytes,
) -> bytes:
    with tempfile.TemporaryDirectory(
        prefix="private_snapshot_"
    ) as directory:
        path = (
            Path(
                directory
            )
            / "snapshot.bin"
        )
        path.write_bytes(
            content
        )

        return path.read_bytes()
