import subprocess
from pathlib import Path


def install_repository(
    repository_url: str,
) -> None:
    checkout = Path(
        "/tmp/plugin-checkout"
    )
    subprocess.run(
        [
            "git",
            "clone",
            repository_url,
            str(checkout),
        ],
        check=True,
    )
    subprocess.run(
        [
            "python",
            str(
                checkout
                / "setup.py"
            ),
            "install",
        ],
        check=True,
    )
