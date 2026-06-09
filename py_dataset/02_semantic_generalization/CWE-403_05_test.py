import os
import socket
import subprocess


def launch_helper() -> None:
    channel = socket.socket(
        socket.AF_UNIX,
        socket.SOCK_STREAM,
    )
    channel.connect(
        "/run/private-signing.sock"
    )
    os.set_inheritable(
        channel.fileno(),
        True,
    )

    subprocess.run(
        [
            "/opt/helpers/report-helper",
        ],
        close_fds=False,
        check=True,
    )
