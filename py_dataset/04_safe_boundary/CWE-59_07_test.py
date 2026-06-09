import os
import stat


def require_regular_file(
    path: str,
) -> None:
    metadata = os.lstat(
        path
    )

    if stat.S_ISLNK(
        metadata.st_mode
    ):
        raise ValueError(
            "symbolic links are not allowed"
        )

    if not stat.S_ISREG(
        metadata.st_mode
    ):
        raise ValueError(
            "regular file required"
        )
