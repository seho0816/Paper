import subprocess


def synchronize(
    source: str,
    destination: str,
) -> None:
    subprocess.run(
        [
            "rsync",
            "-a",
            "--",  # Explicitly mark the end of options to prevent argument injection
            source,
            destination,
        ],
        check=True,
    )
