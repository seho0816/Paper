import os
import stat


def write_file(
    path: str,
    content: bytes,
) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_NOFOLLOW,
    )

    try:
        metadata = os.fstat(
            descriptor
        )

        if not stat.S_ISREG(
            metadata.st_mode
        ):
            raise ValueError(
                "regular file required"
            )

        os.write(
            descriptor,
            content,
        )
    finally:
        os.close(
            descriptor
        )

