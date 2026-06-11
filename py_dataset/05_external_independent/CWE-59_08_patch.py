import os


def overwrite_upload(
    destination: str,
    content: bytes,
) -> None:
    descriptor = os.open(
        destination,
        os.O_WRONLY
        | os.O_TRUNC
        | os.O_NOFOLLOW,
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
