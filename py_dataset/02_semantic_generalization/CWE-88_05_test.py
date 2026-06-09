import subprocess


def synchronize(
    source: str,
    destination: str,
) -> None:
    subprocess.run(
        [
            "rsync",
            "-a",
            source,
            destination,
        ],
        check=True,
    )
