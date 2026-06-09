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

    # CWE-276: Incorrect Default Permissions - The call to os.umask(0) is removed.
    # Instead, the file permissions are explicitly set to be restrictive (0o600)
    # after the file is written, ensuring only the owner can read/write the token.
    credential_file_path = Path(
        "cli-credential.txt"
    )
    credential_file_path.write_text(
        arguments.token,
        encoding="utf-8",
    )
    os.chmod(credential_file_path, 0o600)
