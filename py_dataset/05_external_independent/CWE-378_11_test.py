import os
import tempfile


def resolve_create_export(
    _root,
    _info,
    content: bytes,
) -> dict:
    descriptor, path = tempfile.mkstemp(
        suffix=".zip"
    )
    os.fchmod(
        descriptor,
        0o640,
    )
    os.write(
        descriptor,
        content,
    )
    os.close(
        descriptor
    )

    return {
        "path": path,
    }
