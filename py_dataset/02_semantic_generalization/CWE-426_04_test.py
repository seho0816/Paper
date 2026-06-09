import os


def start_backup(
    source: str,
    destination: str,
) -> None:
    os.execvp(
        "rsync",
        [
            "rsync",
            "-a",
            source,
            destination,
        ],
    )
