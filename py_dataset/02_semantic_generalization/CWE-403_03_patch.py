import os
import subprocess


def launch_renderer() -> None:
    configuration = open(
        "/etc/application/private.env",
        "rb",
    )
    # CWE-403: Exposure of File Descriptor to Unintended Child Process
    # The original code explicitly made the file descriptor inheritable by setting the flag to True.
    # To prevent the child process from inheriting this sensitive file descriptor,
    # the inheritable flag is set to False. This ensures that even with
    # close_fds=False in subprocess.run, this specific file descriptor
    # will not be inherited by the child process.
    os.set_inheritable(
        configuration.fileno(),
        False,  # Changed from True to False to prevent inheritance
    )

    subprocess.run(
        [
            "/usr/bin/node",
            "renderer.js",
        ],
        close_fds=False,
        check=True,
    )
