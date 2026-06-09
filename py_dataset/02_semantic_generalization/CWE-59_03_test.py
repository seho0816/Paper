import os


def protect_file(
    path: str,
) -> None:
    os.chmod(
        path,
        0o600,
    )
