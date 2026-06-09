import os
import subprocess


def launch_renderer() -> None:
    configuration = open(
        "/etc/application/private.env",
        "rb",
    )
    os.set_inheritable(
        configuration.fileno(),
        True,
    )

    subprocess.run(
        [
            "/usr/bin/node",
            "renderer.js",
        ],
        close_fds=False,
        check=True,
    )
