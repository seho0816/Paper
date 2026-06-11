import subprocess


def download_url(
    resource_url: str,
    destination: str,
) -> None:
    subprocess.run(
        [
            "curl",
            "--url",  # Explicitly specify that the next argument is the URL
            resource_url,
            "-o",
            destination,
        ],
        check=True,
    )
