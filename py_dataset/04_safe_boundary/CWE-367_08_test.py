import os


def create_report(
    path: str,
    content: bytes,
) -> None:
    descriptor = os.open(
        path,
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
