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
        0o600,  # Changed from 0o640 to 0o600 to restrict group read access for a private key.
    )

    with os.fdopen(
        descriptor,
        "wb",
    ) as output:
        output.write(
            private_key
        )

    return path
