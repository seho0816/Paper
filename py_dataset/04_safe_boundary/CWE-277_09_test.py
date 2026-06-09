import os
from pathlib import Path


def write_private_record(
    target: Path,
    content: bytes,
) -> None:
    descriptor = os.open(
        target,
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL,
        0o600,
    )
    try:
        os.write(
            descriptor,
            content,
        )
    finally:
        os.close(
            descriptor
        )
