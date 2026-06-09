import os
import tempfile


def write_temporary_private_key(
    private_key: bytes,
) -> str:
    descriptor, path = tempfile.mkstemp(
        prefix="private_key_",
        suffix=".pem",
    )
    os.fchmod(
        descriptor,
        0o640,
    )

    with os.fdopen(
        descriptor,
        "wb",
    ) as output:
        output.write(
            private_key
        )

    return path
