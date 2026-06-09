import os
import subprocess


def start_worker(
    worker_path: str,
) -> None:
    token_file = open(
        "/run/secrets/worker-token",
        "rb",
    )
    os.set_inheritable(
        token_file.fileno(),
        True,
    )

    subprocess.Popen(
        [
            worker_path,
        ],
        close_fds=False,
    )
