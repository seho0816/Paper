import subprocess
from pathlib import Path

import requests


def run_installer(
    installer_url: str,
) -> None:
    response = requests.get(
        installer_url,
        timeout=10,
    )
    response.raise_for_status()

    path = Path(
        "/tmp/installer.sh"
    )
    path.write_bytes(
        response.content
    )

    subprocess.run(
        [
            "/bin/sh",
            str(path),
        ],
        check=True,
    )
