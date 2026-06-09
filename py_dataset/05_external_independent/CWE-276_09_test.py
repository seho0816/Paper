import argparse
import os
from pathlib import Path


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--token",
        required=True,
    )
    arguments = parser.parse_args()

    os.umask(
        0
    )
    Path(
        "cli-credential.txt"
    ).write_text(
        arguments.token,
        encoding="utf-8",
    )
