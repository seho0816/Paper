import os
import subprocess


def launch_trusted_worker(
    data_fd: int,
) -> None:
    os.set_inheritable(
        data_fd,
        False,
    )

    subprocess.run(
        [
            "/opt/trusted/worker",
        ],
        close_fds=True,
        pass_fds=(
            data_fd,
        ),
        check=True,
    )

