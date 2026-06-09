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
        0o640,
    )
    os.write(
        descriptor,
        bundle,
    )
    os.close(
        descriptor
    )

    return path
