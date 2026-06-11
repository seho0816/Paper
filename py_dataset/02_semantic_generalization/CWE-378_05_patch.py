import os
import tempfile


def create_certificate_bundle(
    bundle: bytes,
) -> str:
    descriptor, path = tempfile.mkstemp(
        suffix=".p12"
    )
    os.fchmod(
        descriptor,
        0o600,  # CWE-378: Changed permissions from 0o640 to 0o600 for sensitive file
    )
    os.write(
        descriptor,
        bundle,
    )
    os.close(
        descriptor
    )

    return path
