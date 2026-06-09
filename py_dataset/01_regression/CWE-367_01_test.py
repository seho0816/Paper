import os


def read_authorized_file(
    path: str,
) -> bytes:
    if not os.access(
        path,
        os.R_OK,
    ):
        raise PermissionError(
            path
        )

    with open(
        path,
        "rb",
    ) as source:
        return source.read()
