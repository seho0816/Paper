import subprocess
import urllib.parse


def install_plugin_package(
    package_url: str,
) -> None:
    parsed_url = urllib.parse.urlparse(package_url)
    if parsed_url.scheme == 'http':
        raise ValueError("Insecure HTTP scheme detected for package URL. Use HTTPS for secure download.")

    subprocess.run(
        [
            "pip",
            "install",
            package_url,
        ],
        check=True,
    )
