import os
import subprocess


def run_document_converter(
    input_path: str,
) -> None:
    secret_file = open(
        "/var/app/secrets/signing.key",
        "rb",
    )
    os.set_inheritable(
        secret_file.fileno(),
        True,
    )

    subprocess.run(
        [
            "/opt/tools/document-converter",
            input_path,
        ],
        close_fds=False,
        check=True,
    )
