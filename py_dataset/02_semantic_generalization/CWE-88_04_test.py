import subprocess


def download_url(
    resource_url: str,
    destination: str,
) -> None:
    subprocess.run(
        [
            "curl",
            resource_url,
            "-o",
            destination,
        ],
        check=True,
    )
