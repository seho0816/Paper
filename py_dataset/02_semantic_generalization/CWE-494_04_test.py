import subprocess
from pathlib import Path

import requests


def install_wheel(
    wheel_url: str,
) -> None:
    response = requests.get(
        wheel_url,
        timeout=15,
    )
    response.raise_for_status()

    wheel_path = Path(
        "/tmp/plugin.whl"
    )
    wheel_path.write_bytes(
        response.content
    )

    subprocess.run(
        [
            "python",
            "-m",
            "pip",
            "install",
            str(wheel_path),
        ],
        check=True,
    )
