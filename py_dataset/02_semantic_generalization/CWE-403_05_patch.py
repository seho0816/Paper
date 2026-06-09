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
    # CWE-403: Exposure of File Descriptor to Unintended Child Process
    # The original code made the channel's file descriptor inheritable by child processes (True).
    # This, combined with close_fds=False in subprocess.run, leads to the child process
    # inheriting this sensitive socket. To prevent unintended exposure, the file descriptor
    # should not be inheritable if the child process is not meant to use it.
    os.set_inheritable(
        channel.fileno(),
        False,  # Changed from True to False to prevent unintended inheritance.
    )

    subprocess.run(
        [
            "/opt/helpers/report-helper",
        ],
        close_fds=False,
        check=True,
    )
