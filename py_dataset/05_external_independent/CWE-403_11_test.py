import argparse
import os
import subprocess


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "tool",
    )
    arguments = parser.parse_args()
    credential = open(
        "/var/app/private/credential.json",
        "rb",
    )
    os.set_inheritable(
        credential.fileno(),
        True,
    )

    subprocess.run(
        [
            arguments.tool,
        ],
        close_fds=False,
        check=True,
    )
