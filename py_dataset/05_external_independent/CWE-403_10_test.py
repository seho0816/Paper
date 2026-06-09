import os
import subprocess

from celery import shared_task


@shared_task
def convert_private_document(
    input_path: str,
) -> None:
    secret = open(
        "/run/secrets/converter-key",
        "rb",
    )
    os.set_inheritable(
        secret.fileno(),
        True,
    )

    subprocess.run(
        [
            "/opt/tools/converter",
            input_path,
        ],
        close_fds=False,
        check=True,
    )
