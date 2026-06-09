import os
import tempfile


def save_temporary(
    content: bytes,
) -> str:
    descriptor, path = tempfile.mkstemp(
        prefix="upload_",
        suffix=".bin",
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

    return path
