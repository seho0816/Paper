import subprocess


def resize_image(
    source: str,
    destination: str,
) -> None:
    subprocess.run(
        [
            "convert",
            source,
            "-resize",
            "800x800",
            destination,
        ],
        check=True,
    )
