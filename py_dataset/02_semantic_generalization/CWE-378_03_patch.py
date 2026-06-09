import os
import tempfile


def write_customer_export(
    content: bytes,
) -> str:
    descriptor, path = tempfile.mkstemp(
        prefix="customers_",
        suffix=".zip",
    )
    os.write(
        descriptor,
        content,
    )
    os.close(
        descriptor
    )

    return path
